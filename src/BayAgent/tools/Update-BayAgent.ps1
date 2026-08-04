<#
Update-BayAgent.ps1

Purpose
- Download a versioned BayAgent zip from HTTPS (e.g., GitHub Releases)
- Verify SHA256
- Expand into:   C:\AllBirdies\BayAgent\releases\<version>\
- Promote into:  C:\AllBirdies\BayAgent\current\
- Sign installed scripts (BayAgent.ps1 and any .ps1/.psm1/.psd1 in current) to satisfy AllSigned,
  RFC 3161 timestamped so the signature outlives the signing certificate's own expiry
- Optionally request restart by writing: C:\AllBirdies\BayAgent\control\restart.host

ZIP structure supported:
A) Files at root (BayAgent.ps1, manifest.json, etc.)
B) A single top-level folder containing those files
(Anything deeper than one folder is not recommended.)

Typical usage (via StartProcess BayCommand):

  powershell.exe -NoProfile -File "C:\AllBirdies\BayAgent\tools\Update-BayAgent.ps1" `
    -Version "1.1.8" `
    -PackageUrl "https://github.com/<owner>/<repo>/releases/download/<tag>/BayAgent-1.1.8.zip" `
    -Sha256 "<sha256>" `
    -RequestRestart

PACKAGE HOSTING -- GitHub Releases, no authentication
  PackageUrl must be an HTTPS URL that needs no credentials. All three fleet packages
  (BayAgent, SessionDisplay, PromosPack) are hosted as GitHub Release assets and are
  fetched with a plain Invoke-WebRequest, exactly as Update-SessionDisplay.ps1 and
  Update-PromosPack.ps1 have always done.

  Dataverse file-column hosting is RETIRED. It required a Bearer token handed over in
  control\dvtoken.tmp plus MSCRMCallerID / CallerObjectId impersonation headers, because
  an S2S (client_credentials) token cannot read a file column directly. That in turn
  forced prvActOnBehalfOfAnotherUser at GLOBAL scope onto the ABG Bay AGent role -- a
  standing privilege to act as any user in the org, held by an unattended kiosk PC, for
  the sole purpose of fetching a zip. Moving the package to GitHub removes the need for
  the token, the impersonation headers and the privilege.

INTEGRITY IS UNCHANGED BY THIS MOVE
  What protects the fleet is the SHA256 check below plus the Authenticode signing pass
  that follows it -- not the transport. The package bytes are identical whichever host
  serves them, so the expected hash does not change when hosting moves. A tampered or
  truncated download fails the hash and the script throws before anything is staged.

#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Version,
  [Parameter(Mandatory = $true)][string]$PackageUrl,
  [Parameter(Mandatory = $true)][string]$Sha256,

  [string]$BaseDir = "C:\AllBirdies\BayAgent",

  # If you provide -CertThumbprint we'll use that exact cert.
  [string]$CertThumbprint = "",

  # If you don't provide thumbprint, we find a Code Signing cert.
  # Optional hint to pick the right one if you have multiple.
  [string]$CertSubjectContains = "ABG",

  # Sign the promoted scripts in current\ (recommended for AllSigned)
  [switch]$SignAfterInstall = $true,

  # Create restart marker for watchdog/host
  [switch]$RequestRestart,

  # Logging
  [string]$LogPath = "C:\AllBirdies\BayAgent\logs\Update-BayAgent.log",

  # Download retry count
  [int]$DownloadRetries = 3,

  # RFC 3161 timestamp server used when signing installed scripts. A timestamped
  # Authenticode signature stays valid after the signing certificate itself expires;
  # an untimestamped one does not. Must be HTTP, not HTTPS -- Set-AuthenticodeSignature
  # does not support HTTPS timestamp URLs. Override only if DigiCert's responder
  # endpoint moves or a different CA is used.
  [string]$TimeStampServer = "http://timestamp.digicert.com"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Ensure-Dir([string]$p) {
  if (-not (Test-Path -LiteralPath $p)) {
    New-Item -ItemType Directory -Path $p -Force | Out-Null
  }
}

function Write-Log([string]$msg) {
  try {
    Ensure-Dir (Split-Path -Parent $LogPath)
    $line = ("{0} {1}" -f (Get-Date).ToString("s"), $msg)
    Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8
  } catch {
    # Never block update due to logging
  }
}

function Get-Sha([string]$path) {
  return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Invoke-Robo([string]$src, [string]$dst, [string[]]$extraArgs) {
  Ensure-Dir $dst
  $args = @($src, $dst) + $extraArgs
  $p = Start-Process -FilePath "robocopy.exe" -ArgumentList $args -Wait -PassThru -NoNewWindow
  # Robocopy exit codes: 0-7 are success-ish; >=8 indicates failure
  if ($p.ExitCode -ge 8) { throw "Robocopy failed with exit code $($p.ExitCode)" }
  return $p.ExitCode
}

function Clear-StaleDataverseToken() {
  # BayAgent writes its live OAuth bearer token to control\dvtoken.tmp before launching
  # ANY powershell.exe StartProcess child, not just this one. Nothing else on the machine
  # deletes it. Downloads no longer need that token, so shred it on every run rather than
  # leaving a usable Dataverse credential sitting in plaintext on an unattended kiosk.
  # This is a strict improvement on the previous behaviour, which only deleted the file
  # when the package URL happened to be a Dataverse URL -- a GitHub-hosted update already
  # left it behind indefinitely.
  $tokenFile = Join-Path $BaseDir "control\dvtoken.tmp"
  try {
    if (Test-Path -LiteralPath $tokenFile) {
      Remove-Item -LiteralPath $tokenFile -Force -ErrorAction Stop
      Write-Log "Removed stale control\dvtoken.tmp (downloads no longer use a Dataverse token)."
    }
  } catch {
    Write-Log "WARNING: could not remove control\dvtoken.tmp: $($_.Exception.Message)"
  }
}

function Test-IsDataverseUrl([string]$url) {
  return ($url -match '\.crm\d*\.dynamics\.com/')
}

function Download-FileWithRetry([string]$url, [string]$outFile, [int]$retries) {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

  # Dataverse file-column hosting is retired -- refuse it loudly rather than attempting a
  # fetch that can only ever 401. An S2S token cannot read a file column without
  # impersonation headers, and this script no longer sends them by design. Failing here
  # with an explanation beats three silent retries and a generic timeout.
  if (Test-IsDataverseUrl $url) {
    # NOTE the parentheses around the concatenation: "a" + "b" -f $x parses as "a" + ("b" -f $x),
    # which silently drops the placeholder and prints a URL-less message on an unmanned machine.
    $msg = ("PackageUrl points at Dataverse ({0}). Dataverse file-column hosting is retired: " +
            "this script no longer impersonates a user to read file columns. Publish the package " +
            "as a GitHub Release asset and set the Fleet.BayAgent.PackageUrl ConfigItem to that " +
            "URL -- the SHA256 does not change, because the package bytes do not change.")
    throw ($msg -f $url)
  }

  $lastErr = $null
  for ($i = 1; $i -le $retries; $i++) {
    try {
      Write-Log "Downloading (attempt $i/$retries): $url"
      Invoke-WebRequest -Uri $url -OutFile $outFile -UseBasicParsing -MaximumRedirection 10
      if (-not (Test-Path -LiteralPath $outFile)) { throw "Download completed but file missing: $outFile" }
      if ((Get-Item -LiteralPath $outFile).Length -lt 100) { Write-Log "Warning: downloaded file is very small (<100 bytes). Verify URL." }
      return
    } catch {
      $lastErr = $_
      Write-Log "Download attempt $i failed: $($_.Exception.Message)"
      Start-Sleep -Seconds ([Math]::Min(10, 2 * $i))
    }
  }
  throw "Failed to download after $retries attempts. Last error: $($lastErr.Exception.Message)"
}

function Get-CodeSigningCert() {
  if (-not [string]::IsNullOrWhiteSpace($CertThumbprint)) {
    $tp = $CertThumbprint.Replace(" ", "")
    $c = Get-ChildItem Cert:\LocalMachine\My\$tp -ErrorAction SilentlyContinue
    if (-not $c) { throw "Code signing cert not found by thumbprint in LocalMachine\My: $CertThumbprint" }
    return $c
  }

  $cands = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object {
      $_.EnhancedKeyUsageList.FriendlyName -contains "Code Signing"
    })

  if ($cands.Count -eq 0) {
    throw "No Code Signing certificate found in Cert:\LocalMachine\My"
  }

  if (-not [string]::IsNullOrWhiteSpace($CertSubjectContains)) {
    $filtered = @($cands | Where-Object { $_.Subject -like "*$CertSubjectContains*" })
    if ($filtered.Count -gt 0) { $cands = $filtered }
  }

  # pick the one with the latest expiry
  return ($cands | Sort-Object NotAfter -Descending | Select-Object -First 1)
}

function Sign-File([string]$path, $cert, [string]$timeStampServer) {
  if (-not (Test-Path -LiteralPath $path)) { return $false }
  $ext = [IO.Path]::GetExtension($path).ToLowerInvariant()
  if ($ext -notin @(".ps1", ".psm1", ".psd1")) { return $false }

  # Signing modifies file content: do it only after all copying is complete.
  Set-AuthenticodeSignature -FilePath $path -Certificate $cert -TimeStampServer $timeStampServer | Out-Null
  $sig = Get-AuthenticodeSignature -FilePath $path

  if ($sig.Status -ne "Valid") {
    throw "Signature invalid for $path. Status=$($sig.Status) Message=$($sig.StatusMessage)"
  }
  if ($null -eq $sig.TimeStamperCertificate) {
    # Set-AuthenticodeSignature can silently sign WITHOUT a timestamp and still report
    # Status=Valid if the timestamp server was unreachable or rejected the request --
    # that untimestamped signature stops validating the moment the signing cert expires.
    # Hard-fail rather than ship that silently.
    throw "Signature for $path is Valid but UNTIMESTAMPED (server: $timeStampServer). Refusing to ship an untimestamped release -- it would stop validating when the signing certificate expires."
  }

  return $true
}

# ------------------ MAIN ------------------

Write-Log "----"
Write-Log "Starting update. Version=$Version Url=$PackageUrl BaseDir=$BaseDir SignAfterInstall=$([bool]$SignAfterInstall) TimeStampServer=$TimeStampServer RequestRestart=$([bool]$RequestRestart)"

# Standard folders
$StagingDir  = Join-Path $BaseDir "staging"
$ReleasesDir = Join-Path $BaseDir "releases"
$CurrentDir  = Join-Path $BaseDir "current"
$ControlDir  = Join-Path $BaseDir "control"

Ensure-Dir $BaseDir
Ensure-Dir $StagingDir
Ensure-Dir $ReleasesDir
Ensure-Dir $CurrentDir
Ensure-Dir $ControlDir

# Downloads are unauthenticated now; shred any bearer token BayAgent left for us.
Clear-StaleDataverseToken

# Paths for this version
$zipPath   = Join-Path $StagingDir ("BayAgent-{0}.zip" -f $Version)
$expandDir = Join-Path $StagingDir ("expand-{0}" -f $Version)
$relDir    = Join-Path $ReleasesDir $Version

# Download
Download-FileWithRetry -url $PackageUrl -outFile $zipPath -retries $DownloadRetries

# Verify SHA
$actual   = Get-Sha $zipPath
$expected = $Sha256.ToLowerInvariant().Replace(" ", "")
Write-Log "SHA expected=$expected actual=$actual"
if ($actual -ne $expected) { throw "SHA256 mismatch. Expected $expected, got $actual" }

# Expand
Write-Log "Expanding zip to $expandDir"
if (Test-Path -LiteralPath $expandDir) { Remove-Item -LiteralPath $expandDir -Recurse -Force }
Ensure-Dir $expandDir
Expand-Archive -LiteralPath $zipPath -DestinationPath $expandDir -Force

# Determine content root (zip root vs single top folder)
$contentRoot = $expandDir
$children = @(Get-ChildItem -LiteralPath $expandDir)
if ($children.Count -eq 1 -and $children[0].PSIsContainer) {
  $contentRoot = $children[0].FullName
}
Write-Log "Content root is $contentRoot"

# Sanity check
if (-not (Test-Path -LiteralPath (Join-Path $contentRoot "BayAgent.ps1"))) {
  Write-Log "WARNING: BayAgent.ps1 not found at content root. Files: $(@(Get-ChildItem -LiteralPath $contentRoot | Select-Object -ExpandProperty Name) -join ', ')"
  throw "Package missing BayAgent.ps1 at expected location. Check zip structure."
}
if (-not (Test-Path -LiteralPath (Join-Path $contentRoot "manifest.json"))) {
  Write-Log "WARNING: manifest.json not found at content root. The agent may report an old version."
  # We don't hard-fail because you might not be using manifest for versioning yet.
}

# Stage into releases\<version>
Write-Log "Staging into release folder $relDir"
if (Test-Path -LiteralPath $relDir) { Remove-Item -LiteralPath $relDir -Recurse -Force }
Ensure-Dir $relDir
Invoke-Robo $contentRoot $relDir @("/MIR") | Out-Null

# ---- Sign in release folder first (safe) ----
$signCount = 0
if ($SignAfterInstall) {
  Write-Log "Signing enabled. Locating code-signing certificate..."
  $cert = Get-CodeSigningCert
  Write-Log "Using cert Subject=$($cert.Subject) Thumbprint=$($cert.Thumbprint) NotAfter=$($cert.NotAfter)"

  # Sign BayAgent.ps1 inside the release folder first
  $relAgentPath = Join-Path $relDir "BayAgent.ps1"
  if (-not (Test-Path $relAgentPath)) { throw "Release missing BayAgent.ps1: $relAgentPath" }

  if (Sign-File -path $relAgentPath -cert $cert -timeStampServer $TimeStampServer) { $signCount++ }

  # Sign any shipped modules/scripts in the release folder too
  $toSign = @(Get-ChildItem -LiteralPath $relDir -Recurse -File |
    Where-Object { $_.Extension -in ".ps1", ".psm1", ".psd1" })

  foreach ($f in $toSign) {
    if ($f.FullName -ieq $relAgentPath) { continue }
    if (Sign-File -path $f.FullName -cert $cert -timeStampServer $TimeStampServer) { $signCount++ }
  }

  # Verify the release agent signature is Valid AND timestamped before touching current
  $sig = Get-AuthenticodeSignature -FilePath $relAgentPath
  if ($sig.Status -ne "Valid") {
    throw "Release BayAgent.ps1 signature invalid ($($sig.Status)): $($sig.StatusMessage)"
  }
  if ($null -eq $sig.TimeStamperCertificate) {
    throw "Release BayAgent.ps1 signature is Valid but UNTIMESTAMPED. Refusing to promote to current."
  }

  Write-Log "Signing complete in release folder. SignedFiles=$signCount"
}

# ---- Promote release -> current only after signing succeeded ----
Write-Log "Promoting SIGNED release -> current ($CurrentDir)"
Invoke-Robo $relDir $CurrentDir @("/MIR") | Out-Null

# ---- If the package ships a tools/ folder, merge into $BaseDir\tools ----
$pkgTools = Join-Path $relDir "tools"
if (Test-Path -LiteralPath $pkgTools) {
  $destTools = Join-Path $BaseDir "tools"
  Ensure-Dir $destTools
  Write-Log "Package includes tools/ -- merging into $destTools"
  # /E = copy subdirs including empty; no /MIR to avoid deleting scripts not in the package
  Invoke-Robo $pkgTools $destTools @("/E") | Out-Null
  Write-Log "Tools merge complete."
}

# Request restart (watchdog/host should honor)
if ($RequestRestart) {
  $marker = Join-Path $ControlDir "restart.host"
  $msg = "restart requested $(Get-Date).ToUniversalTime().ToString('s')Z version=$Version"
  Set-Content -LiteralPath $marker -Value $msg -Encoding UTF8
  Write-Log "Wrote restart marker: $marker"
}

Write-Log "Update complete OK. Version=$Version"
Write-Output ("OK: Updated BayAgent to {0}. ReleaseDir={1}. CurrentDir={2}. SignedFiles={3}. RestartRequested={4}" -f $Version, $relDir, $CurrentDir, $signCount, [bool]$RequestRestart)
