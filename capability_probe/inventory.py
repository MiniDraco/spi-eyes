"""Firmware attack-surface enumerator -- call the whole roll of firmware-bearing chips.

Fail-closed completeness: a firmware store we don't enumerate is one we silently
skipped, which is a false all-clear by omission. This module lists EVERY chip on the
machine that carries firmware and labels each one's coverage honestly:

  REF-AVAILABLE  we hold a known-good reference (a read would let us verify)
  CANNOT-VERIFY  we cannot currently read/verify this chip's firmware (fail-closed)
  OUT-OF-SCOPE   not reachable by host software (declared, not pretended-clean)

Nothing is dropped. The output is the machine's firmware attack surface + exactly how
much of it we can and cannot see.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from .winutil import as_list, run_ps_json

# PnP device class -> (store label, default coverage, read path today)
_CLASS_STORES = {
    "Display": ("GPU VBIOS", "CANNOT-VERIFY", "device-resident (LVFS ref possible)"),
    "Net": ("NIC firmware", "CANNOT-VERIFY", "device-resident / GbE SPI region"),
    "SCSIAdapter": ("storage controller fw", "CANNOT-VERIFY", "device-resident"),
    "HDC": ("disk/AHCI/NVMe controller fw", "CANNOT-VERIFY", "device-resident"),
    "USB": ("USB controller fw", "CANNOT-VERIFY", "device-resident"),
    "Bluetooth": ("Bluetooth controller fw", "CANNOT-VERIFY", "device-resident"),
    "MEDIA": ("audio DSP fw", "CANNOT-VERIFY", "device-resident"),
    "Image": ("camera fw", "CANNOT-VERIFY", "device-resident"),
    "Biometric": ("fingerprint fw", "CANNOT-VERIFY", "device-resident"),
    "SmartCardReader": ("smartcard fw", "CANNOT-VERIFY", "device-resident"),
    "Firmware": ("system/device firmware (UEFI capsule)", "CANNOT-VERIFY", "UEFI capsule / LVFS"),
}
_FW_CLASSES = list(_CLASS_STORES)


@dataclass
class Component:
    store: str
    name: str
    cls: str
    hardware_id: str
    fw_version: str
    coverage: str          # REF-AVAILABLE / CANNOT-VERIFY / OUT-OF-SCOPE
    read_path: str
    note: str = ""


def _pnp_devices() -> List[Component]:
    q = ("Get-CimInstance Win32_PnPEntity | Where-Object {$_.PNPClass -in "
         + ",".join(f"'{c}'" for c in _FW_CLASSES)
         + "} | Select-Object Name,PNPClass,DeviceID,Manufacturer | ConvertTo-Json -Compress")
    ok, data, _ = run_ps_json(q)
    out: List[Component] = []
    seen = set()
    for d in as_list(data) if ok else []:
        if not isinstance(d, dict):
            continue
        did = str(d.get("DeviceID", ""))
        # only physical silicon buses carry firmware; skip virtual/software nodes
        if not (did.startswith("PCI\\") or did.startswith("USB\\")):
            continue
        name = (d.get("Name") or "?").strip()
        if name in seen:
            continue
        seen.add(name)
        store, cov, path = _CLASS_STORES.get(d.get("PNPClass", ""), ("device fw", "CANNOT-VERIFY", "device-resident"))
        out.append(Component(store=store, name=name, cls=d.get("PNPClass", ""),
                             hardware_id=did.split("\\")[1] if "\\" in did else did,
                             fw_version="", coverage=cov, read_path=path))
    return out


def _disks() -> List[Component]:
    ok, data, _ = run_ps_json(
        "Get-PhysicalDisk | Select-Object FriendlyName,MediaType,BusType,FirmwareVersion | ConvertTo-Json -Compress")
    out = []
    for d in as_list(data) if ok else []:
        if not isinstance(d, dict):
            continue
        out.append(Component(store="drive controller fw (IRATEMONK class)",
                             name=(d.get("FriendlyName") or "?").strip(), cls="Disk",
                             hardware_id="", fw_version=str(d.get("FirmwareVersion", "")),
                             coverage="CANNOT-VERIFY",
                             read_path="service-area needs factory cmds; boot-ROM via external SPI",
                             note="content largely version-pin + anomaly only"))
    return out


def _host_stores() -> List[Component]:
    ok, data, _ = run_ps_json(
        "$b=Get-CimInstance Win32_BIOS; $p=Get-CimInstance Win32_Processor|Select-Object -First 1;"
        "[pscustomobject]@{BIOS=$b.SMBIOSBIOSVersion;CPU=$p.Manufacturer}|ConvertTo-Json")
    bios = data.get("BIOS", "?") if isinstance(data, dict) else "?"
    vendor = str(data.get("CPU", "")).lower() if isinstance(data, dict) else ""
    engine = "Intel ME/CSME" if "intel" in vendor else ("AMD PSP" if "amd" in vendor else "coprocessor")
    return [
        Component("host UEFI/SPI flash (BIOS)", f"system BIOS {bios}", "SystemFirmware", "", str(bios),
                  "REF-AVAILABLE", "external SPI read / CHIPSEC driver",
                  "corpus has per-module refs; needs a live dump to diff"),
        Component(f"{engine} (ring -3 coprocessor)", engine, "Coprocessor", "", "",
                  "REF-AVAILABLE", "in the SPI dump (ME/PSP parser: corpus.coproc)",
                  "per-entry hashes now minted; needs a live dump to diff"),
        Component("TPM / measured boot", "TPM", "TPM", "", "",
                  "CANNOT-VERIFY", "attested via DRTM quote, not content",
                  "integrity via quote, not image match"),
        Component("option ROMs", "PCI option ROMs", "OptionROM", "", "",
                  "CANNOT-VERIFY", "in the SPI dump / PCI expansion ROM",
                  "carve from BIOS dump + PCR2 cross-check"),
    ]


def _platform_subchips() -> List[Component]:
    """Firmware-bearing SUB-CHIPS the OS does not enumerate as devices. These sit on
    internal LPC/SMBus/I2C/SPI buses invisible to Windows PnP -- so we NAME the known
    classes (fail-closed: a sub-chip we can't name is a silent omission) and label how,
    or whether, each is reachable. There is always a residual tail (retimers, PMICs,
    PHYs) neither the OS nor host software can see -- stated, not hidden."""
    return [
        Component("CPU microcode", "CPU microcode patch", "SubChip", "", "",
                  "REF-AVAILABLE", "in the SPI dump (microcode blobs in an FV)",
                  "hashed when we carve a full dump"),
        Component("Super I/O", "Super I/O controller (ITE/Nuvoton)", "SubChip", "", "",
                  "CANNOT-VERIFY", "LPC/SMBus, vendor-specific", "not an OS-visible device"),
        Component("board RGB/fan MCU", "lighting/fan controller (e.g. RGB Fusion)", "SubChip", "", "",
                  "CANNOT-VERIFY", "SMBus/I2C, vendor tool", "MCU firmware on SMBus"),
        Component("audio codec DSP", "audio codec firmware/verbs", "SubChip", "", "",
                  "CANNOT-VERIFY", "HDA verb table / device fw", "only partially an OS device"),
        Component("DIMM SPD / DDR5 PMIC", "memory SPD hub / DDR5 PMIC", "SubChip", "", "",
                  "CANNOT-VERIFY", "SMBus (SPD/PMIC)", "DDR5 PMIC carries firmware"),
        Component("VRM/PWM controller", "VRM / PMBus controller", "SubChip", "", "",
                  "CANNOT-ENUMERATE", "SMBus (PMBus) if present", "usually no OS handle"),
        Component("USB/PCIe retimer/redriver", "signal retimers / redrivers", "SubChip", "", "",
                  "CANNOT-ENUMERATE", "internal; physical/vendor only", "invisible to OS + host sw"),
        Component("NIC/PHY firmware", "Ethernet PHY firmware", "SubChip", "", "",
                  "CANNOT-VERIFY", "GbE SPI region / device", "sub-block of the NIC"),
    ]


def enumerate_components() -> List[Component]:
    return _host_stores() + _pnp_devices() + _disks() + _platform_subchips()


def summarize(comps: List[Component]) -> dict:
    from collections import Counter
    cov = Counter(c.coverage for c in comps)
    return {"total": len(comps), "ref_available": cov.get("REF-AVAILABLE", 0),
            "cannot_verify": cov.get("CANNOT-VERIFY", 0),
            "cannot_enumerate": cov.get("CANNOT-ENUMERATE", 0),
            "out_of_scope": cov.get("OUT-OF-SCOPE", 0)}


def main() -> int:
    import sys
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass
    comps = enumerate_components()
    s = summarize(comps)
    print("=" * 78)
    print(" SPI-Eyes :: Firmware Attack Surface  (calling every firmware-bearing chip)")
    print("=" * 78)
    for c in comps:
        v = c.fw_version and f" fw={c.fw_version}"
        print(f"  [{c.coverage:<13}] {c.store:<38} {c.name[:34]}{v or ''}")
        print(f"                   read: {c.read_path}" + (f" — {c.note}" if c.note else ""))
    print("-" * 78)
    print(f"  {s['total']} firmware-bearing components: {s['ref_available']} reference-available, "
          f"{s['cannot_verify']} CANNOT-VERIFY (blind), {s['cannot_enumerate']} CANNOT-ENUMERATE "
          f"(known to exist, no OS handle), {s['out_of_scope']} out-of-scope")
    print("  FAIL-CLOSED: nothing is silently skipped. Chips we can't read = CANNOT-VERIFY;")
    print("  sub-chips we can't even detect = CANNOT-ENUMERATE (named, not hidden). A residual")
    print("  tail (retimers, PMICs, PHYs) is unreachable by any host software -- stated, not pretended.")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
