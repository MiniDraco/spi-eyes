"""Windows evidence probes (read-only, no kernel driver).

Each probe returns list[Evidence] and never raises. A failed/denied query becomes
CANNOT_VERIFY or NOT_ASSESSED with an `error` string -- never a false negative.

NOTE for review: several probes here are genuine IOC/anomaly detectors (BYOVD
firmware-write drivers, dbx currency, HPA/DCO). On a machine believed at risk,
their ANOMALOUS output is to be treated as possibly real. Fail-open is forbidden;
fail-loud is encouraged.
"""
from __future__ import annotations

import base64
import glob
import os
import struct
from datetime import datetime, timezone
from typing import Dict, List

from .model import Evidence, Layer, Verdict
from .winutil import run_ps, run_ps_json, have, as_list

# ---- Win32_DeviceGuard enums ---------------------------------------------------
DG_SERVICES = {1: "Credential Guard", 2: "HVCI (Memory Integrity)",
               3: "System Guard Secure Launch (DRTM)", 4: "SMM Firmware Measurement"}
DG_PROPS = {1: "Hypervisor support", 2: "Secure Boot", 3: "DMA protection",
            4: "Secure Memory Overwrite", 5: "NX protections",
            6: "SMM security mitigations", 7: "Mode-based execution control",
            8: "APIC virtualization"}

# ---- known raw-hardware-access / firmware-write drivers (BYOVD watch) -----------
# These expose physical memory / MSR / PCI / SPI primitives. Presence is HOW firmware
# implants get flashed (LoJax + TrickBoot used RWEverything's RwDrv.sys). Some are also
# used by legit overclock/monitoring tools -> flag as IOC to investigate, not proof.
# Seed list; expand from the LOLDrivers project (loldrivers.io).
FIRMWARE_ACCESS_DRIVERS: Dict[str, str] = {
    "rwdrv.sys": "RWEverything - raw PCI/MSR/SPI access; used by LoJax & TrickBoot to flash BIOS",
    "asrdrv101.sys": "ASRock raw I/O driver (known BYOVD)",
    "asrdrv103.sys": "ASRock raw I/O driver (known BYOVD)",
    "winring0.sys": "WinRing0 raw MSR/PCI (common in OC/monitor tools AND abused)",
    "winring0x64.sys": "WinRing0 raw MSR/PCI (common in OC/monitor tools AND abused)",
    "inpoutx64.sys": "InpOut raw port I/O",
    "directio64.sys": "DirectIO raw port/memory access",
    "glckio2.sys": "GIGABYTE raw I/O driver (known BYOVD)",
    "gdrv.sys": "GIGABYTE raw I/O driver (known BYOVD)",
    "atillk64.sys": "ATI/AMD raw I/O driver (known BYOVD)",
    "phymemx64.sys": "physical memory access driver",
    "physmem.sys": "physical memory access driver",
}


def _parse_efi_sig_lists(data: bytes):
    """Return (count, sha256_hashes[]) across all EFI_SIGNATURE_LIST records."""
    off, total, hashes = 0, 0, []
    n = len(data)
    while off + 28 <= n:
        list_size, hdr_size, sig_size = struct.unpack_from("<III", data, off + 16)
        if list_size < 28 or sig_size == 0 or off + list_size > n:
            break
        body = list_size - 28 - hdr_size
        if body < 0 or sig_size == 0 or body % sig_size != 0:
            break
        cnt = body // sig_size
        total += cnt
        # SHA256 sig entries are 48 bytes: 16 owner GUID + 32 hash
        if sig_size == 48:
            base = off + 28 + hdr_size
            for i in range(cnt):
                h = data[base + i * 48 + 16: base + i * 48 + 48]
                hashes.append(h.hex())
        off += list_size
    return total, hashes


# ---------------------------------------------------------------------------------
def probe_machine_identity() -> List[Evidence]:
    script = (
        "$b=Get-CimInstance Win32_BIOS; $c=Get-CimInstance Win32_ComputerSystem;"
        "$m=Get-CimInstance Win32_BaseBoard; $p=Get-CimInstance Win32_Processor|Select-Object -First 1;"
        "$rd=''; try{$rd=$b.ReleaseDate.ToString('yyyy-MM-dd')}catch{};"
        "[pscustomobject]@{Vendor=$c.Manufacturer;Model=$c.Model;SKU=$c.SystemSKUNumber;"
        "Board=$m.Product;BoardVer=$m.Version;BIOSVendor=$b.Manufacturer;"
        "BIOSVersion=$b.SMBIOSBIOSVersion;BIOSRelease=$rd;"
        "CPU=$p.Name;CPUVendor=$p.Manufacturer}|ConvertTo-Json"
    )
    ok, data, err = run_ps_json(script)
    ev: List[Evidence] = []
    if not ok or not isinstance(data, dict):
        return [Evidence("machine_identity", Layer.CAPABILITY, "SMBIOS identity unreadable",
                         Verdict.NOT_ASSESSED, Verdict.CANNOT_VERIFY, True,
                         "OS-API (spoofable)", error=err or "no data")]
    finding = f"{data.get('Vendor','?')} {data.get('Model','?')} / BIOS {data.get('BIOSVersion','?')} ({data.get('CPU','?')})"
    ev.append(Evidence("machine_identity", Layer.CAPABILITY, finding,
                       Verdict.NOT_ASSESSED, Verdict.CANNOT_VERIFY, True,
                       "OS-API (spoofable)", detail=data))
    # BIOS age -> stale firmware is an exposure signal
    rd = str(data.get("BIOSRelease", "")).strip()
    try:
        if rd:
            age_days = (datetime.now(timezone.utc) - datetime.strptime(rd, "%Y-%m-%d").replace(tzinfo=timezone.utc)).days
            years = age_days / 365.25
            stale = years >= 3
            ev.append(Evidence("bios_age", Layer.SUSCEPTIBILITY,
                               f"BIOS dated {rd} ({years:.1f}y old)" + (" -> likely missing firmware security fixes" if stale else ""),
                               Verdict.ANOMALOUS if stale else Verdict.CANNOT_VERIFY,
                               Verdict.CANNOT_VERIFY, True, "OS-API (spoofable)",
                               detail={"release": rd, "years": round(years, 1), "stale": stale}))
    except Exception:  # noqa: BLE001
        pass
    return ev


def probe_tpm() -> List[Evidence]:
    script = (
        "try{$t=Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftTpm' "
        "-ClassName Win32_Tpm -ErrorAction Stop;"
        "[pscustomobject]@{Spec=$t.SpecVersion;MfrId=$t.ManufacturerIdTxt;"
        "MfrVer=$t.ManufacturerVersion;Enabled=$t.IsEnabled_InitialValue;"
        "Activated=$t.IsActivated_InitialValue}|ConvertTo-Json}"
        "catch{Write-Output ('ERR:'+$_.Exception.Message)}"
    )
    ok, data, err = run_ps_json(script)
    if not ok or not isinstance(data, dict):
        msg = data if isinstance(data, str) else (err or "no data")
        denied = "denied" in msg.lower()
        return [Evidence("tpm", Layer.CAPABILITY,
                         "TPM state UNKNOWN - Win32_Tpm needs elevation" if denied
                         else "TPM not present / not enabled in firmware",
                         Verdict.NOT_ASSESSED if denied else Verdict.CANNOT_VERIFY,
                         Verdict.CANNOT_VERIFY, True, "OS-API (spoofable); needs admin",
                         detail={"assessed": not denied, "tpm20": (None if denied else False)},
                         error=msg)]
    spec = str(data.get("Spec", "")).strip()
    is20 = spec.startswith("2.0")
    mfr = str(data.get("MfrId", "")).strip()
    ftpm = mfr.upper() in ("INTC", "AMD", "MSFT")
    kind = "fTPM (shares fate with ME/PSP)" if ftpm else "dTPM (discrete; bus-sniff/interposer risk)"
    data.update({"assessed": True, "tpm20": is20, "kind": kind})
    return [Evidence("tpm", Layer.CAPABILITY,
                     f"TPM {spec.split(',')[0] or '?'} present, {mfr or '?'} [{kind}]",
                     Verdict.CANNOT_VERIFY, Verdict.CANNOT_VERIFY, True,
                     "OS-API (spoofable); quote path is hardware-rooted (Phase 2)", detail=data)]


def probe_deviceguard() -> List[Evidence]:
    script = (
        "try{$d=Get-CimInstance -Namespace 'root/Microsoft/Windows/DeviceGuard' "
        "-ClassName Win32_DeviceGuard -ErrorAction Stop;"
        "[pscustomobject]@{Avail=$d.AvailableSecurityProperties;"
        "Configured=$d.SecurityServicesConfigured;Running=$d.SecurityServicesRunning;"
        "VBS=$d.VirtualizationBasedSecurityStatus}|ConvertTo-Json}"
        "catch{Write-Output ('ERR:'+$_.Exception.Message)}"
    )
    ok, data, err = run_ps_json(script)
    if not ok or not isinstance(data, dict):
        msg = data if isinstance(data, str) else (err or "no data")
        return [Evidence("deviceguard", Layer.CAPABILITY, "DeviceGuard state unreadable",
                         Verdict.CANNOT_VERIFY, Verdict.CANNOT_VERIFY, True,
                         "OS-API (spoofable)", error=msg)]
    running = [int(x) for x in as_list(data.get("Running"))]
    configured = [int(x) for x in as_list(data.get("Configured"))]
    avail = [int(x) for x in as_list(data.get("Avail"))]
    hvci_running = 2 in running
    drtm_running = 3 in running
    drtm_configured = 3 in configured
    dma_avail = 3 in avail
    data.update({"running_named": [DG_SERVICES.get(x, x) for x in running],
                 "available_named": [DG_PROPS.get(x, x) for x in avail],
                 "hvci_running": hvci_running, "drtm_running": drtm_running,
                 "drtm_configured": drtm_configured, "dma_protection": dma_avail})
    if drtm_running:
        finding = "DRTM / System Guard Secure Launch RUNNING -> earned CLEAN(Above-SMM) path reachable"
    elif drtm_configured:
        finding = "DRTM configured but not running -> CLEAN path reachable after enabling Secure Launch"
    else:
        finding = "DRTM / Secure Launch NOT active -> no software CLEAN path on this machine (external read only)"
    ev = [Evidence("deviceguard", Layer.CAPABILITY, finding,
                   Verdict.CANNOT_VERIFY, Verdict.CANNOT_VERIFY, True,
                   "OS-API (spoofable); DRTM quote itself is hardware-rooted", detail=data)]
    ev.append(Evidence("kernel_dma", Layer.SUSCEPTIBILITY,
                       ("Kernel DMA Protection available" if dma_avail
                        else "Kernel DMA Protection NOT available -> Thunderbolt/PCIe DMA attack surface open"),
                       Verdict.CANNOT_VERIFY if dma_avail else Verdict.ANOMALOUS,
                       Verdict.CANNOT_VERIFY, True, "OS-API (spoofable)",
                       detail={"dma_protection": dma_avail}))
    return ev


def probe_measured_boot_log() -> List[Evidence]:
    path = r"C:\Windows\Logs\MeasuredBoot"
    try:
        logs = glob.glob(os.path.join(path, "*.log"))
        readable = sum(1 for lg in logs[:3] if _readable(lg))
        finding = (f"measured-boot log present ({len(logs)} files) -> event-log cross-check feasible"
                   if logs else "no measured-boot logs -> measured boot may be off")
        return [Evidence("measured_boot_log", Layer.CAPABILITY, finding, Verdict.CANNOT_VERIFY,
                         Verdict.CANNOT_VERIFY, True, "OS filesystem (spoofable)",
                         detail={"count": len(logs), "readable_sampled": readable})]
    except Exception as e:  # noqa: BLE001
        return [Evidence("measured_boot_log", Layer.CAPABILITY, "measured-boot log check failed",
                         Verdict.NOT_ASSESSED, Verdict.CANNOT_VERIFY, True, "OS filesystem", error=str(e))]


def _readable(p: str) -> bool:
    try:
        with open(p, "rb") as fh:
            fh.read(64)
        return True
    except OSError:
        return False


def probe_secure_boot() -> List[Evidence]:
    ev: List[Evidence] = []
    ok, out, err = run_ps("try{[string](Confirm-SecureBootUEFI)}catch{'ERR:'+$_.Exception.Message}")
    state = out.strip()
    low = state.lower()
    if "not supported" in low or "legacy" in low:
        ev.append(Evidence("boot_mode", Layer.SUSCEPTIBILITY,
                           "LEGACY BIOS boot (no Secure Boot) -> pre-UEFI-security-model machine",
                           Verdict.ANOMALOUS, Verdict.CANNOT_VERIFY, True, "OS-API", detail={"uefi": False}))
    elif low.startswith("true") or low.startswith("false"):
        on = low.startswith("true")
        ev.append(Evidence("secure_boot", Layer.SUSCEPTIBILITY, f"Secure Boot is {'ON' if on else 'OFF'} (UEFI)",
                           Verdict.ANOMALOUS if not on else Verdict.CANNOT_VERIFY,
                           Verdict.CANNOT_VERIFY, True, "OS-API (spoofable)", detail={"enabled": on, "uefi": True}))
    else:
        ev.append(Evidence("secure_boot", Layer.SUSCEPTIBILITY,
                           "Secure Boot state unreadable (needs elevation)",
                           Verdict.NOT_ASSESSED, Verdict.CANNOT_VERIFY, True, "OS-API; needs admin",
                           error=state or err))
    ev.append(_probe_dbx())
    ev.extend(_probe_sb_keys())
    return ev


def _probe_dbx() -> Evidence:
    ok, out, err = run_ps("try{$x=(Get-SecureBootUEFI dbx).Bytes;[Convert]::ToBase64String($x)}"
                          "catch{'ERR:'+$_.Exception.Message}")
    out = out.strip()
    if out.startswith("ERR") or not ok or not out:
        return Evidence("dbx_currency", Layer.SUSCEPTIBILITY,
                        "dbx unreadable (needs elevation) -> revocation currency unknown",
                        Verdict.NOT_ASSESSED, Verdict.CANNOT_VERIFY, True,
                        "OS-API; needs admin", error=out or err)
    try:
        count, hashes = _parse_efi_sig_lists(base64.b64decode(out))
    except Exception as e:  # noqa: BLE001
        return Evidence("dbx_currency", Layer.SUSCEPTIBILITY, "dbx decode failed",
                        Verdict.NOT_ASSESSED, Verdict.CANNOT_VERIFY, True, "OS-API", error=str(e))
    stale = count < 200  # post-2023 dbx carries several hundred; low count => likely un-updated
    finding = (f"dbx has {count} revocations "
               + ("-> LIKELY STALE (BlackLotus/BootHole class may be un-revoked)" if stale
                  else "-> populated (confirm vs current UEFI Forum dbxupdate.bin for true currency)"))
    return Evidence("dbx_currency", Layer.SUSCEPTIBILITY, finding,
                    Verdict.ANOMALOUS if stale else Verdict.CANNOT_VERIFY,
                    Verdict.CANNOT_VERIFY, True, "OS-API (spoofable)",
                    detail={"entry_count": count, "looks_stale": stale,
                            "note": "true currency = diff vs official dbxupdate.bin (bundle in Phase 1b+)"})


def _probe_sb_keys() -> List[Evidence]:
    """Enumerate db/KEK/PK sizes and flag the Microsoft 3rd-party UEFI CA (broad trust)."""
    ok, out, err = run_ps(
        "try{$db=(Get-SecureBootUEFI db).Bytes;"
        "$s=[System.Text.Encoding]::ASCII.GetString($db);"
        "[pscustomobject]@{dbLen=$db.Length;ThirdParty=($s -match 'Microsoft Corporation UEFI CA 2011')}|ConvertTo-Json}"
        "catch{'ERR:'+$_.Exception.Message}")
    if not ok or not isinstance(out, str) or out.startswith("ERR"):
        # run_ps returns string; try json parse
        pass
    ok2, data, err2 = run_ps_json(
        "try{$db=(Get-SecureBootUEFI db).Bytes;"
        "$s=[System.Text.Encoding]::ASCII.GetString($db);"
        "[pscustomobject]@{dbLen=$db.Length;ThirdParty=[bool]($s -match 'Microsoft.*UEFI CA 2011')}|ConvertTo-Json}"
        "catch{Write-Output ('ERR:'+$_.Exception.Message)}")
    if not ok2 or not isinstance(data, dict):
        return [Evidence("secure_boot_keys", Layer.SUSCEPTIBILITY,
                         "db/KEK/PK not enumerable (needs elevation)",
                         Verdict.NOT_ASSESSED, Verdict.CANNOT_VERIFY, True, "OS-API; needs admin",
                         error=(data if isinstance(data, str) else err2))]
    third = bool(data.get("ThirdParty"))
    finding = ("db present; Microsoft 3rd-Party UEFI CA is TRUSTED -> broad option-ROM/Linux trust surface"
               if third else "db present; 3rd-party UEFI CA not detected (narrower trust)")
    return [Evidence("secure_boot_keys", Layer.SUSCEPTIBILITY, finding,
                     Verdict.ANOMALOUS if third else Verdict.CANNOT_VERIFY,
                     Verdict.CANNOT_VERIFY, True, "OS-API (spoofable)",
                     detail={"db_len": data.get("dbLen"), "third_party_ca": third})]


def probe_driver_loadability() -> List[Evidence]:
    ok, out, _ = run_ps(
        "try{(Get-CimInstance -Namespace 'root/Microsoft/Windows/DeviceGuard' "
        "-ClassName Win32_DeviceGuard).SecurityServicesRunning -join ','}catch{''}")
    hvci = "2" in (out or "").split(",")
    _, blk, _ = run_ps("try{(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config' "
                       "-Name VulnerableDriverBlocklistEnable -ErrorAction Stop)."
                       "VulnerableDriverBlocklistEnable}catch{'?'}")
    _, ts, _ = run_ps("try{bcdedit /enum '{current}' | Select-String testsigning}catch{'?'}")
    testsigning = "yes" in (ts or "").lower()
    if hvci:
        finding = ("HVCI (Memory Integrity) ON -> CHIPSEC/Platbox kernel driver load very likely BLOCKED; "
                   "susceptibility layer needs an offline/WinPE path")
        v = Verdict.ANOMALOUS
    else:
        finding = ("HVCI OFF -> CHIPSEC driver may load, but load is observable to a resident implant "
                   "and needs elevation/attestation-signing")
        v = Verdict.CANNOT_VERIFY
    return [Evidence("driver_loadability", Layer.CAPABILITY, finding, v, Verdict.CANNOT_VERIFY, True,
                     "OS-API (spoofable)",
                     detail={"hvci_running": hvci, "vuln_driver_blocklist": (blk or "").strip(),
                             "testsigning_on": testsigning,
                             "note": "actual driver-load test is Phase 1c (opt-in)"})]


def probe_byovd_drivers() -> List[Evidence]:
    """IOC: raw-hardware-access / firmware-write drivers present = flashing capability."""
    ok, data, err = run_ps_json(
        "Get-CimInstance Win32_SystemDriver | Select-Object Name,State,PathName | ConvertTo-Json -Compress")
    if not ok:
        return [Evidence("byovd_drivers", Layer.INFECTION, "driver list unreadable",
                         Verdict.NOT_ASSESSED, Verdict.CANNOT_VERIFY, True, "OS-API", error=err)]
    rows = as_list(data)
    hits = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        pn = (r.get("PathName") or r.get("Name") or "")
        base = os.path.basename(str(pn)).lower()
        if base in FIRMWARE_ACCESS_DRIVERS:
            hits.append({"driver": base, "state": r.get("State"),
                         "path": pn, "risk": FIRMWARE_ACCESS_DRIVERS[base]})
    if hits:
        names = ", ".join(f"{h['driver']}({h['state']})" for h in hits)
        return [Evidence("byovd_drivers", Layer.INFECTION,
                         f"FIRMWARE-ACCESS DRIVER(S) PRESENT: {names} -- capable of flashing firmware; investigate",
                         Verdict.ANOMALOUS, Verdict.CANNOT_VERIFY, False,
                         "loaded-driver inventory (real IOC)",
                         detail={"hits": hits, "note": "how LoJax/TrickBoot flashed BIOS; may also be legit OC tools"})]
    return [Evidence("byovd_drivers", Layer.INFECTION,
                     f"no known firmware-write drivers among {len(rows)} drivers (seed list; expand from LOLDrivers)",
                     Verdict.CANNOT_VERIFY, Verdict.CANNOT_VERIFY, True, "loaded-driver inventory",
                     detail={"driver_count": len(rows)})]


def probe_option_rom_surface() -> List[Evidence]:
    ok, data, err = run_ps_json(
        "Get-CimInstance Win32_PnPEntity | Where-Object {$_.PNPClass -in "
        "'Display','Net','SCSIAdapter','HDC','MediaControllers'} | "
        "Select-Object Name,Manufacturer,PNPClass | ConvertTo-Json -Compress")
    rows = as_list(data) if ok else []
    devs = [r for r in rows if isinstance(r, dict)]
    if devs:
        return [Evidence("option_rom_surface", Layer.INFECTION,
                         f"{len(devs)} device(s) that can carry option ROMs (GPU/NIC/storage) -> content unverifiable without a dump",
                         Verdict.CANNOT_VERIFY, Verdict.CANNOT_VERIFY, True, "PnP inventory (surface only)",
                         detail={"devices": [{"name": d.get("Name"), "class": d.get("PNPClass")} for d in devs]})]
    return [Evidence("option_rom_surface", Layer.INFECTION, "option-ROM-bearing devices not enumerable",
                     Verdict.NOT_ASSESSED, Verdict.CANNOT_VERIFY, True, "PnP inventory", error=err)]


def probe_me_psp() -> List[Evidence]:
    ok, data, err = run_ps_json(
        "$cpu=(Get-CimInstance Win32_Processor|Select-Object -First 1).Manufacturer;"
        "$mei=Get-CimInstance Win32_PnPEntity|Where-Object {$_.Name -match "
        "'Management Engine|MEI|Platform Security|PSP'}|Select-Object -Expand Name;"
        "[pscustomobject]@{CPUVendor=$cpu;MEI=@($mei)}|ConvertTo-Json -Compress")
    if not ok or not isinstance(data, dict):
        return [Evidence("me_psp", Layer.INFECTION, "ME/PSP presence not enumerable",
                         Verdict.NOT_ASSESSED, Verdict.CANNOT_VERIFY, True, "PnP inventory", error=err)]
    vendor = str(data.get("CPUVendor", "")).lower()
    engine = "Intel ME/CSME" if "intel" in vendor else ("AMD PSP" if "amd" in vendor else "unknown coprocessor")
    mei = as_list(data.get("MEI"))
    return [Evidence("me_psp", Layer.INFECTION,
                     f"{engine} present (ring -3 coprocessor); version/integrity NOT assessed (needs vendor tool/driver)",
                     Verdict.NOT_ASSESSED, Verdict.CANNOT_VERIFY, True, "PnP inventory (self-report)",
                     detail={"engine": engine, "cpu_vendor": vendor, "mei_devices": mei,
                             "note": "Intel: cross-check ME ver vs INTEL-SA-00086 fix; AMD PSP needs deeper probe"})]


def probe_storage() -> List[Evidence]:
    ev: List[Evidence] = []
    ok, data, err = run_ps_json(
        "Get-PhysicalDisk | Select-Object FriendlyName,MediaType,BusType,FirmwareVersion,"
        "@{n='SizeGB';e={[math]::Round($_.Size/1GB,1)}} | ConvertTo-Json")
    disks = as_list(data) if ok else []
    if disks:
        names = ", ".join(f"{d.get('FriendlyName','?')} fw={d.get('FirmwareVersion','?')}"
                          for d in disks if isinstance(d, dict))
        ev.append(Evidence("drive_firmware", Layer.INFECTION, f"{len(disks)} disk(s): {names}",
                           Verdict.CANNOT_VERIFY, Verdict.CANNOT_VERIFY, True,
                           "controller self-report (spoofable)", detail={"disks": disks}))
    else:
        ev.append(Evidence("drive_firmware", Layer.INFECTION, "drive firmware not enumerable",
                           Verdict.NOT_ASSESSED, Verdict.CANNOT_VERIFY, True, "controller self-report",
                           error=err or "no data"))
    ev.append(_probe_hpa_dco())
    return ev


def _probe_hpa_dco() -> Evidence:
    if not have("smartctl"):
        return Evidence("hpa_dco", Layer.INFECTION,
                        "HPA/DCO NOT assessed (install smartmontools: READ NATIVE MAX vs IDENTIFY)",
                        Verdict.NOT_ASSESSED, Verdict.CANNOT_VERIFY, True, "needs smartmontools",
                        detail={"tool": None})
    import subprocess
    findings = []
    try:
        scan = subprocess.run(["smartctl", "--scan"], capture_output=True, text=True, timeout=30)
        devs = [ln.split()[0] for ln in scan.stdout.splitlines() if ln.strip()]
        for dev in devs[:8]:
            r = subprocess.run(["smartctl", "-i", dev], capture_output=True, text=True, timeout=30)
            txt = r.stdout.lower()
            hidden = ("hpa" in txt and "enabled" in txt) or "dco" in txt
            findings.append({"dev": dev, "hpa_or_dco_mentioned": hidden})
    except Exception as e:  # noqa: BLE001
        return Evidence("hpa_dco", Layer.INFECTION, "HPA/DCO probe via smartctl failed",
                        Verdict.NOT_ASSESSED, Verdict.CANNOT_VERIFY, True, "smartctl", error=str(e))
    flagged = [f for f in findings if f["hpa_or_dco_mentioned"]]
    if flagged:
        return Evidence("hpa_dco", Layer.INFECTION,
                        f"HPA/DCO hidden-area indicators on {len(flagged)} drive(s) -> investigate",
                        Verdict.ANOMALOUS, Verdict.CANNOT_VERIFY, False, "ATA IDENTIFY via smartctl",
                        detail={"drives": findings})
    return Evidence("hpa_dco", Layer.INFECTION, f"no HPA/DCO hidden area indicated ({len(findings)} drive(s))",
                    Verdict.CANNOT_VERIFY, Verdict.CANNOT_VERIFY, True, "ATA IDENTIFY via smartctl",
                    detail={"drives": findings})


def probe_firmware_surface() -> List[Evidence]:
    """Roll-call EVERY firmware-bearing chip; fail-closed completeness (no silent skips)."""
    from .inventory import enumerate_components, summarize
    comps = enumerate_components()
    s = summarize(comps)
    finding = (f"{s['total']} firmware-bearing chips enumerated: {s['ref_available']} reference-available, "
               f"{s['cannot_verify']} CANNOT-VERIFY (blind) -- run `python -m capability_probe.inventory` for the roll")
    return [Evidence("firmware_surface", Layer.INFECTION, finding,
                     Verdict.CANNOT_VERIFY, Verdict.CANNOT_VERIFY, True, "PnP + host-store inventory",
                     detail={"summary": s, "components": [c.__dict__ for c in comps]})]


ALL_PROBES = [
    probe_machine_identity,
    probe_tpm,
    probe_deviceguard,
    probe_measured_boot_log,
    probe_secure_boot,
    probe_driver_loadability,
    probe_byovd_drivers,
    probe_firmware_surface,
    probe_option_rom_surface,
    probe_me_psp,
    probe_storage,
]


def run() -> List[Evidence]:
    out: List[Evidence] = []
    for fn in ALL_PROBES:
        try:
            out.extend(fn())
        except Exception as e:  # noqa: BLE001
            out.append(Evidence(fn.__name__, Layer.CAPABILITY, f"probe crashed: {e}",
                                Verdict.NOT_ASSESSED, Verdict.CANNOT_VERIFY, True, "n/a", error=str(e)))
    return out
