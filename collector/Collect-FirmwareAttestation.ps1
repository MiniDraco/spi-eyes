<#
  SPI-Eyes :: Firmware Attestation Collector  (hand-off data capture)
  ------------------------------------------------------------------------------
  PURPOSE  Capture the DRTM / TPM / measured-boot / Secure Boot data needed to
           develop the SPI-Eyes "earned-CLEAN" engine, from a Secured-core /
           System-Guard-capable Windows machine. Run once; send back two files.

  SAFETY   * READ-ONLY. Loads no driver. Writes NOTHING to firmware, TPM, or BCD.
           * ZERO network activity. It only writes two local files next to itself.
           * You may review this script before running it. Everything it does is
             a Get-/read operation. Nothing is transmitted anywhere by this tool.

  PRIVACY  It collects firmware security *configuration* + measured-boot logs. Those
           logs can contain machine identifiers. Pass  -Anonymize  to hash the
           hostname/serials. REVIEW the .txt before sharing if unsure.

  USAGE    Right-click -> "Run with PowerShell"   (it will request Administrator),
           or:   powershell -ExecutionPolicy Bypass -File Collect-FirmwareAttestation.ps1
           Anonymized:   ... -File Collect-FirmwareAttestation.ps1 -Anonymize

  OUTPUT   FirmwareAttest-<host>-<timestamp>.json   (machine-readable, for the dev)
           FirmwareAttest-<host>-<timestamp>.txt    (human-readable summary)
           -> send BOTH back.
  ------------------------------------------------------------------------------
#>
[CmdletBinding()]
param([switch]$Anonymize)

# ---- self-elevate (needs admin for TPM / Secure Boot / measured-boot logs) -------
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Host "Requesting elevation (UAC)..." -ForegroundColor Yellow
    $argl = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"")
    if ($Anonymize) { $argl += "-Anonymize" }
    Start-Process powershell -Verb RunAs -ArgumentList $argl
    exit
}

$ErrorActionPreference = "SilentlyContinue"
$result = [ordered]@{}
$log = New-Object System.Collections.ArrayList
function Note($msg) { [void]$log.Add([string]$msg); Write-Host $msg }
function Redact($s) {
    if (-not $Anonymize -or [string]::IsNullOrEmpty([string]$s)) { return $s }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $h = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$s))
    return "anon:" + ([BitConverter]::ToString($h) -replace '-', '').Substring(0, 12)
}
function B64([byte[]]$b) { if ($b) { [Convert]::ToBase64String($b) } else { $null } }

$hostName = Redact($env:COMPUTERNAME)
$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")

Note "=============================================================================="
Note " SPI-Eyes :: Firmware Attestation Collector"
Note " host=$hostName  utc=$stamp  anonymize=$Anonymize"
Note " READ-ONLY. No driver. No network. Two local files only."
Note "=============================================================================="

$result.meta = [ordered]@{
    tool = "spi-eyes/collector"; version = "0.1"; host = $hostName; utc = $stamp
    anonymized = [bool]$Anonymize; powershell = $PSVersionTable.PSVersion.ToString()
}

# ---- 1. system / firmware identity ----------------------------------------------
Note "`n[1] System & firmware identity"
try {
    $bios = Get-CimInstance Win32_BIOS
    $cs = Get-CimInstance Win32_ComputerSystem
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    $os = Get-CimInstance Win32_OperatingSystem
    $fwType = try { (Get-ComputerInfo -Property BiosFirmwareType).BiosFirmwareType } catch { "?" }
    $result.identity = [ordered]@{
        OsName = $os.Caption; OsBuild = $os.BuildNumber
        Manufacturer = Redact($cs.Manufacturer); Model = Redact($cs.Model); SKU = Redact($cs.SystemSKUNumber)
        BiosFirmwareType = "$fwType"; BIOSVendor = $bios.Manufacturer
        BIOSVersion = $bios.SMBIOSBIOSVersion; BIOSReleaseDate = "$($bios.ReleaseDate)"
        CPU = $cpu.Name; CPUVendor = $cpu.Manufacturer; Serial = Redact($bios.SerialNumber)
    }
    Note ("    {0} {1} / {2} / BIOS {3} / firmware={4}" -f $result.identity.Manufacturer,
        $result.identity.Model, $result.identity.CPU, $result.identity.BIOSVersion, $fwType)
} catch { Note "    ERROR: $($_.Exception.Message)"; $result.identity = @{ error = "$($_.Exception.Message)" } }

# ---- 2. DeviceGuard / VBS / DRTM (THE decisive capability for earned-CLEAN) -------
Note "`n[2] DeviceGuard / VBS / System Guard (DRTM)  <-- the decisive capability"
try {
    $dg = Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop
    $svcMap = @{1 = "CredentialGuard"; 2 = "HVCI"; 3 = "SystemGuardSecureLaunch(DRTM)"; 4 = "SMMFirmwareMeasurement" }
    $propMap = @{1 = "Hypervisor"; 2 = "SecureBoot"; 3 = "DMAProtection"; 4 = "SecureMemoryOverwrite";
        5 = "NX"; 6 = "SMMMitigations"; 7 = "MBEC"; 8 = "APICVirt" }
    $running = @($dg.SecurityServicesRunning); $configured = @($dg.SecurityServicesConfigured); $avail = @($dg.AvailableSecurityProperties)
    $drtmRunning = $running -contains 3
    $result.deviceguard = [ordered]@{
        VirtualizationBasedSecurityStatus = $dg.VirtualizationBasedSecurityStatus
        AvailableSecurityProperties = $avail
        AvailableSecurityProperties_named = @($avail | ForEach-Object { $propMap[[int]$_] })
        SecurityServicesConfigured = $configured
        SecurityServicesConfigured_named = @($configured | ForEach-Object { $svcMap[[int]$_] })
        SecurityServicesRunning = $running
        SecurityServicesRunning_named = @($running | ForEach-Object { $svcMap[[int]$_] })
        DRTM_running = $drtmRunning
    }
    Note ("    VBS status={0}  running=[{1}]" -f $dg.VirtualizationBasedSecurityStatus, ($result.deviceguard.SecurityServicesRunning_named -join ", "))
    if ($drtmRunning) { Note "    *** DRTM / Secure Launch is RUNNING -- this machine is USEFUL for Phase 2 dev ***" }
    else { Note "    NOTE: DRTM not running here. Still send data -- 'configured' + event log are useful." }
} catch { Note "    ERROR: $($_.Exception.Message)"; $result.deviceguard = @{ error = "$($_.Exception.Message)" } }

# ---- 3. registry: DeviceGuard scenarios + SecureBoot state -----------------------
Note "`n[3] Registry (DeviceGuard scenarios, SecureBoot state)"
function Dump-RegKey($path) {
    try {
        $k = Get-ItemProperty -Path $path -ErrorAction Stop
        $o = [ordered]@{}
        $k.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { $o[$_.Name] = $_.Value }
        return $o
    } catch { return @{ error = "$($_.Exception.Message)" } }
}
$result.registry = [ordered]@{
    DeviceGuard = Dump-RegKey "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
    HVCI = Dump-RegKey "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
    SystemGuard = Dump-RegKey "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard"
    SecureBootState = Dump-RegKey "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State"
}
Note "    captured DeviceGuard / SystemGuard / SecureBoot registry keys"

# ---- 4. TPM ----------------------------------------------------------------------
Note "`n[4] TPM"
try {
    $tpm = Get-CimInstance -Namespace root/cimv2/Security/MicrosoftTpm -ClassName Win32_Tpm -ErrorAction Stop
    $gt = Get-Tpm 2>$null
    $result.tpm = [ordered]@{
        SpecVersion = $tpm.SpecVersion; ManufacturerId = $tpm.ManufacturerIdTxt; ManufacturerVersion = $tpm.ManufacturerVersion
        Enabled = $tpm.IsEnabled_InitialValue; Activated = $tpm.IsActivated_InitialValue; Owned = $tpm.IsOwned_InitialValue
        TpmPresent = $gt.TpmPresent; TpmReady = $gt.TpmReady
    }
    Note ("    TPM {0}  mfr={1}  ready={2}" -f ($tpm.SpecVersion -split ',')[0], $tpm.ManufacturerIdTxt, $gt.TpmReady)
} catch { Note "    ERROR: $($_.Exception.Message)"; $result.tpm = @{ error = "$($_.Exception.Message)" } }

# ---- 5. measured-boot logs (WBCL / TCG event logs) -- crown jewel for Phase 2 -----
Note "`n[5] Measured-boot event logs (WBCL) -- base64 (to build the event-log parser)"
try {
    $mbDir = Join-Path $env:SystemRoot "Logs\MeasuredBoot"
    $files = Get-ChildItem $mbDir -Filter *.log -ErrorAction Stop | Sort-Object LastWriteTime -Descending | Select-Object -First 4
    $logs = @()
    foreach ($f in $files) {
        try {
            $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
            $logs += [ordered]@{ name = $f.Name; bytes = $bytes.Length; sha256 = (Get-FileHash $f.FullName -Algorithm SHA256).Hash; base64 = (B64 $bytes) }
        } catch {}
    }
    $result.measured_boot_logs = $logs
    Note ("    captured {0} WBCL log(s)" -f $logs.Count)
} catch { Note "    ERROR / none present: $($_.Exception.Message)"; $result.measured_boot_logs = @() }

# ---- 6. Secure Boot vars (state + dbx/db/KEK/PK as base64) ------------------------
Note "`n[6] Secure Boot variables (state, dbx, db, KEK, PK)"
$sb = [ordered]@{}
try { $sb.SecureBootEnabled = [bool](Confirm-SecureBootUEFI) } catch { $sb.SecureBootEnabled = "ERR: $($_.Exception.Message)" }
foreach ($v in "dbx", "db", "KEK", "PK") {
    try { $bytes = (Get-SecureBootUEFI $v).Bytes; $sb[$v] = [ordered]@{ len = $bytes.Length; base64 = (B64 $bytes) } }
    catch { $sb[$v] = @{ error = "$($_.Exception.Message)" } }
}
$result.secure_boot = $sb
Note ("    SecureBoot={0}  dbx={1}B  db={2}B" -f $sb.SecureBootEnabled,
    ($(if ($sb.dbx.len) { $sb.dbx.len } else { '?' })), ($(if ($sb.db.len) { $sb.db.len } else { '?' })))

# ---- 7. boot configuration (bcdedit -- Secure Launch / hypervisor flags) ----------
Note "`n[7] Boot configuration (bcdedit)"
try {
    $bcd = (bcdedit /enum "{current}") 2>&1 | Out-String
    $result.bcdedit_current = $bcd
    Note "    captured bcdedit {current}"
} catch { $result.bcdedit_current = "ERR: $($_.Exception.Message)" }

# ---- 8. HSTI (firmware self-reported security bits), best-effort ------------------
Note "`n[8] HSTI (best-effort)"
try {
    $hsti = Get-CimInstance -Namespace root/wmi -ClassName MS_SystemSecurity -ErrorAction Stop
    $result.hsti = ($hsti | Out-String)
    Note "    captured HSTI"
} catch { $result.hsti = "not available: $($_.Exception.Message)"; Note "    HSTI not exposed (normal on many boards)" }

# ---- write outputs ---------------------------------------------------------------
$result.collector_log = $log.ToArray()
$outDir = Split-Path -Parent $PSCommandPath
$base = Join-Path $outDir ("FirmwareAttest-{0}-{1}" -f $hostName, $stamp)
try {
    $result | ConvertTo-Json -Depth 8 | Out-File "$base.json" -Encoding utf8
    $log.ToArray() | Out-File "$base.txt" -Encoding utf8
    Note "`n=============================================================================="
    Note " DONE. SEND THESE TWO FILES BACK:"
    Note "   $base.json"
    Note "   $base.txt"
    Note " (Review the .txt first if you want to confirm what was collected.)"
    Note "=============================================================================="
} catch {
    Write-Host "ERROR writing output: $($_.Exception.Message)" -ForegroundColor Red
}

if ($MyInvocation.InvocationName -ne '.') { Read-Host "`nPress Enter to close" }
