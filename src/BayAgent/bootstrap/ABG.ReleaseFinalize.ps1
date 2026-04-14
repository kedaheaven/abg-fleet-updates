<#
ABG.ReleaseFinalize.ps1 (v2.1 - Count fix)
Step 7 - Release discipline helper for All Birdies BayAgent.

What it does:
1) Creates/updates a release folder under:   C:\AllBirdies\BayAgent\releases\<Version>\
2) Optionally copies files from a staging folder into the release folder
3) Writes/updates manifest.json (version + releasedUtc)
4) Signs all *.ps1 in the release folder with the specified Code Signing certificate
5) Verifies signatures are Valid
6) Switches C:\AllBirdies\BayAgent\current junction to the new release folder
7) Optionally restarts AgentHost/BayAgent via scheduled tasks (preferred)

IMPORTANT (AllSigned):
- This script must be signed before you can run it under LocalMachine=AllSigned.
  You can sign it without running it.

Usage examples (run in elevated PowerShell):
  # 1) Save script to disk, unblock, sign, then run:
  Unblock-File C:\AllBirdies\BayAgent\bootstrap\ABG.ReleaseFinalize.ps1
  $cert = Get-Item Cert:\CurrentUser\My\<thumbprint>
  Set-AuthenticodeSignature C:\AllBirdies\BayAgent\bootstrap\ABG.ReleaseFinalize.ps1 -Certificate $cert

  # 2) Finalize a release folder you already prepared:
  .\ABG.ReleaseFinalize.ps1 -Version "1.4.3-step7.1" -CertThumbprint "<thumbprint>" -Restart

  # 3) Finalize from a staging folder (copies into releases\<Version>\):
  .\ABG.ReleaseFinalize.ps1 -Version "1.4.3-step7.1" -CertThumbprint "<thumbprint>" -SourceDir "C:\AllBirdies\BayAgent\staging" -Restart -HealthCheck

Notes:
- By default, this script assumes a single file: BayAgent.ps1 in the release folder, but will sign any *.ps1 present.
- It does NOT modify bootstrap scripts (AgentHost/Watchdog). Keep those signed separately.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Version,

    [Parameter(Mandatory=$true)]
    [string]$CertThumbprint,

    [string]$BaseDir = "C:\AllBirdies\BayAgent",

    # Optional: if provided, copies contents of SourceDir into the release folder before signing.
    [string]$SourceDir = "",

    # If true, restarts AgentHost/BayAgent using scheduled tasks after switching current.
    [switch]$Restart,

    # If true, runs BayAgent.ps1 -TokenOnly after switching current (best-effort).
    [switch]$HealthCheck,

    # Override UTC timestamp written to manifest (ISO 8601 Z). Default = now.
    [string]$ReleasedUtc = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Ensure-Dir([string]$p) {
    if (!(Test-Path $p)) { New-Item -ItemType Directory -Force -Path $p | Out-Null }
}

$LogDir = Join-Path $BaseDir "logs"
Ensure-Dir $LogDir
$LogFile = Join-Path $LogDir ("ReleaseFinalize-{0}.log" -f (Get-Date).ToString("yyyyMMdd"))

function Log([string]$msg, [ValidateSet("DEBUG","INFO","WARN","ERROR")] [string]$level="INFO") {
    $ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $line = "$ts [$level] $msg"
    Write-Host $line
    try { Add-Content -Path $LogFile -Value $line } catch {}
}

function Fail([string]$msg) {
    Log $msg "ERROR"
    exit 1
}

function Get-CodeSigningCert([string]$thumb) {
    $thumb = ($thumb -replace '\s','').ToUpperInvariant()
    $cert = $null
    try { $cert = Get-Item ("Cert:\CurrentUser\My\{0}" -f $thumb) -ErrorAction Stop } catch {}
    if (-not $cert) { try { $cert = Get-Item ("Cert:\LocalMachine\My\{0}" -f $thumb) -ErrorAction Stop } catch {} }

    if (-not $cert) { Fail "Code signing cert not found in CurrentUser\My or LocalMachine\My for thumbprint $thumb" }

    # Basic EKU check for Code Signing OID
    $ekuOk = $false
    try {
        foreach ($eku in $cert.EnhancedKeyUsageList) {
            if ($eku.ObjectId.Value -eq "1.3.6.1.5.5.7.3.3") { $ekuOk = $true; break }
        }
    } catch {}

    if (-not $ekuOk) {
        Log "WARNING: Cert does not appear to have Code Signing EKU (OID 1.3.6.1.5.5.7.3.3). Signing may still fail." "WARN"
    }
    return $cert
}

function Write-Manifest([string]$path, [string]$version, [string]$releasedUtcIso) {
    $obj = [ordered]@{
        version     = $version
        releasedUtc = $releasedUtcIso
    }
    $json = $obj | ConvertTo-Json -Depth 3
    # Ensure stable UTF-8 without BOM
    [IO.File]::WriteAllText($path, $json, (New-Object Text.UTF8Encoding($false)))
}

function Copy-ReleaseFiles([string]$src, [string]$dst) {
    if (-not (Test-Path $src)) { Fail "SourceDir not found: $src" }
    Log "Copying from SourceDir => ReleaseDir (best-effort). Source=$src Dest=$dst" "INFO"

    # Copy all files/folders from source into destination
    Get-ChildItem -Path $src -Force | ForEach-Object {
        $target = Join-Path $dst $_.Name
        if ($_.PSIsContainer) {
            Copy-Item -Path $_.FullName -Destination $target -Recurse -Force
        } else {
            Copy-Item -Path $_.FullName -Destination $target -Force
        }
    }
}

function Sign-Files([System.Security.Cryptography.X509Certificates.X509Certificate2]$cert, [string]$dir) {
    $files = @(Get-ChildItem -Path $dir -Recurse -File -Filter *.ps1)
    if ($files.Count -eq 0) { Fail "No .ps1 files found in release folder to sign: $dir" }

    Log ("Signing {0} script(s) in {1}" -f $files.Count, $dir) "INFO"

    foreach ($f in $files) {
        $sig = Set-AuthenticodeSignature -FilePath $f.FullName -Certificate $cert
        if ($sig.Status -ne "Valid") {
            Log ("Signature not valid for {0}. Status={1} Message={2}" -f $f.FullName, $sig.Status, $sig.StatusMessage) "ERROR"
            Fail "Signing failed for $($f.FullName)"
        }
    }
}

function Verify-Signatures([string]$dir) {
    $files = @(Get-ChildItem -Path $dir -Recurse -File -Filter *.ps1)
    foreach ($f in $files) {
        $sig = Get-AuthenticodeSignature -FilePath $f.FullName
        if ($sig.Status -ne "Valid") {
            Log ("INVALID signature: {0}. Status={1} Message={2}" -f $f.FullName, $sig.Status, $sig.StatusMessage) "ERROR"
            Fail "Signature verification failed for $($f.FullName)"
        }
    }
    Log "All signatures verified as Valid." "INFO"
}

function Switch-CurrentJunction([string]$baseDir, [string]$releaseDir) {
    $current = Join-Path $baseDir "current"

    if (-not (Test-IsAdmin)) {
        Fail "Switching the 'current' junction requires elevation. Re-run this script in an elevated PowerShell."
    }

    if (Test-Path $current) {
        Log "Removing existing current link/folder: $current" "INFO"
        cmd /c rmdir "$current" | Out-Null
        Start-Sleep -Milliseconds 200
    }

    Log "Creating junction: $current -> $releaseDir" "INFO"
    cmd /c mklink /J "$current" "$releaseDir" | Out-Null

    if (-not (Test-Path (Join-Path $current "BayAgent.ps1"))) {
        Fail "current junction created, but BayAgent.ps1 not found at: $current\BayAgent.ps1"
    }
}

function Restart-AgentViaTasks {
    param(
        [string]$HostTask = "\ABG Bay Agent",
        [string]$WatchdogTask = "\ABG Host Watchdog"
    )

    if (-not (Test-IsAdmin)) {
        Log "Restart requested, but not elevated. Skipping restart." "WARN"
        return
    }

    Log "Restarting AgentHost via scheduled tasks: End Host task then run Watchdog." "INFO"

    try { schtasks /End /TN $HostTask | Out-Null } catch {}
    Start-Sleep -Seconds 1
    try { schtasks /Run /TN $WatchdogTask | Out-Null } catch {
        Log ("Failed to run watchdog task: {0}" -f $_.Exception.Message) "WARN"
    }
}

function HealthCheck-TokenOnly([string]$baseDir) {
    $agent = Join-Path $baseDir "current\BayAgent.ps1"
    if (-not (Test-Path $agent)) { Log "HealthCheck skipped: current\BayAgent.ps1 not found." "WARN"; return }

    Log "Running TokenOnly health check (best-effort)..." "INFO"
    try {
        & powershell.exe -NoProfile -WindowStyle Hidden -File $agent -TokenOnly | ForEach-Object { Log $_ "DEBUG" }
        Log "HealthCheck completed." "INFO"
    } catch {
        Log ("HealthCheck failed: {0}" -f $_.Exception.Message) "WARN"
    }
}

# ---------------------------
# Main
# ---------------------------
$Version = $Version.Trim()
if ([string]::IsNullOrWhiteSpace($Version)) { Fail "Version is required." }

$releasesDir = Join-Path $BaseDir "releases"
$releaseDir  = Join-Path $releasesDir $Version
Ensure-Dir $releaseDir

if (-not [string]::IsNullOrWhiteSpace($SourceDir)) {
    Copy-ReleaseFiles -src $SourceDir -dst $releaseDir
}

# Write manifest
$releasedUtcIso = $ReleasedUtc
if ([string]::IsNullOrWhiteSpace($releasedUtcIso)) {
    $releasedUtcIso = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}

$manifestPath = Join-Path $releaseDir "manifest.json"
Write-Manifest -path $manifestPath -version $Version -releasedUtcIso $releasedUtcIso
Log "Wrote manifest: $manifestPath (version=$Version releasedUtc=$releasedUtcIso)" "INFO"

# Sign & verify
$cert = Get-CodeSigningCert -thumb $CertThumbprint
Sign-Files -cert $cert -dir $releaseDir
Verify-Signatures -dir $releaseDir

# Switch current to release
Switch-CurrentJunction -baseDir $BaseDir -releaseDir $releaseDir
Log "Switched current to release: $releaseDir" "INFO"

# Optional restart + healthcheck
if ($Restart) {
    Restart-AgentViaTasks
}

if ($HealthCheck) {
    HealthCheck-TokenOnly -baseDir $BaseDir
}

Log "Release finalize complete." "INFO"
exit 0

# SIG # Begin signature block
# MIIFiwYJKoZIhvcNAQcCoIIFfDCCBXgCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUEba+TNmRYVNFLogxXmqG8dhp
# H0ugggMcMIIDGDCCAgCgAwIBAgIQcB7+YhwgR7ZJib3KL4WIcjANBgkqhkiG9w0B
# AQsFADAkMSIwIAYDVQQDDBlBQkcgQmF5QWdlbnQgQ29kZSBTaWduaW5nMB4XDTI2
# MDEwMzExMjAyNloXDTI3MDEwMzExNDAyNlowJDEiMCAGA1UEAwwZQUJHIEJheUFn
# ZW50IENvZGUgU2lnbmluZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
# AMHHQzWuIzBHO6BwscGzuoCN3bquhA+YTha7xYBsvX/eatjwlCpT4buJXeVZvoHQ
# OOcMsKg+kt+taj9s/gv2Arm0rh730JVHtJcSm0X96L+GI29bjydtSFqLl8iAtCvh
# 1EQoakIaxXTVGXKxMNEnhNwIocdDETF1wT1kkZ/bCDZyPY5Y0/iEcRc5CAKAhF/H
# IrIJXd/QL4esRkg1HkmDCOoHD3vZkQAWLgTLchRFE6Uk10RAHwJmpHBWo/pjho0L
# tGNFDRJvgXGpO6hbSSjxu5gyznnDWd2chg/xW6WLJ3dhqFpYIixOR+gBJumVS46F
# 8jFj+hT8MfWxzhpX3NtQf2ECAwEAAaNGMEQwDgYDVR0PAQH/BAQDAgeAMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBTlEn8ZOjY/C0/ILYEj+knQETbTMzAN
# BgkqhkiG9w0BAQsFAAOCAQEATPNqtG54FSKaVvJ/XtuHqccWzTJ3koMG6gq+jlLE
# OiOhQ7auwTNPRy42er59N79LInazh5pEENqFfyorsbzHETk06VEgvagczzUkwnsR
# 0CtRhbeLzaxDu2UGMyoUbeSDC6wpeftBIae0N4Vb+u88Ml3psmyX5vIBduJQ00hL
# kTrgcBL63YcCrfgOmUMxOsTumkDPUPSaA5M9tlEnXo3lSQ/jfzrzJx+CPVg8h3E/
# rssfpBbvvZ7mf0R9Kl7eAMSHw58jrvOuJA2V/7Ws3y9BjiW9YJeuZMCNJFDlI6bG
# 0SPAugVCPD0VTyDtOavtPO1ZmA1nwRA36FKC8ZqWUF2mrzGCAdkwggHVAgEBMDgw
# JDEiMCAGA1UEAwwZQUJHIEJheUFnZW50IENvZGUgU2lnbmluZwIQcB7+YhwgR7ZJ
# ib3KL4WIcjAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZ
# BgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYB
# BAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUEakP/XSFDkp3DxJrF5n9IVvitu4wDQYJ
# KoZIhvcNAQEBBQAEggEATKqYEmZtlZ1wGLD3k6rbqtLN0m6hO33A5z1M8GIIdFdW
# 8BgR3fKSMY3r2BRUOo6v6KMPMFqennkBm4OfyaCsUPJG+/V4pruae9JTZ2rb59x9
# j2GH7J1M5i3iZykpKZ8UOaBF7yR4zvUgSnV2oSEwgbMJkKWJzfUEwl+zeOVafJ9C
# sikejLBz2KuKyoEBmDRsDAXjUiW1Amucob8tjE4fviwD5GowjQYjaFIAeMvh6/t9
# EJh84Hw0B/mutlTJj7fg5mXWMHcpjJuyuaG7oiBDd0iQrZk+1NZKjv5R1bsDDwQn
# eW+umin0YK93NyBBDxzRz8Ln0LZxP2wyCzs2qJcOtg==
# SIG # End signature block
