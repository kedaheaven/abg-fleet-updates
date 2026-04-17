<#
Update-BayAgent.ps1

Purpose
- Download a versioned BayAgent zip from HTTPS (e.g., GitHub Releases)
- Verify SHA256
- Expand into:   C:\AllBirdies\BayAgent\releases\<version>\
- Promote into:  C:\AllBirdies\BayAgent\current\
- Sign installed scripts (BayAgent.ps1 and any .ps1/.psm1/.psd1 in current) to satisfy AllSigned
- Optionally request restart by writing: C:\AllBirdies\BayAgent\control\restart.host

ZIP structure supported:
A) Files at root (BayAgent.ps1, manifest.json, etc.)
B) A single top-level folder containing those files
(Anything deeper than one folder is not recommended.)

Typical usage (via StartProcess BayCommand):

  GitHub (legacy):
  powershell.exe -NoProfile -File "C:\AllBirdies\BayAgent\tools\Update-BayAgent.ps1" `
    -Version "1.0.1" `
    -PackageUrl "https://github.com/<owner>/<repo>/releases/download/<tag>/BayAgent-1.0.1.zip" `
    -Sha256 "<sha256>" `
    -RequestRestart

  Dataverse (preferred):
  powershell.exe -NoProfile -File "C:\AllBirdies\BayAgent\tools\Update-BayAgent.ps1" `
    -Version "1.0.9" `
    -PackageUrl "https://<org>.crm.dynamics.com/api/data/v9.2/build_fleetreleases(<id>)/build_packagefile/$value" `
    -Sha256 "<sha256>" `
    -RequestRestart

  When PackageUrl is a Dataverse URL (.crm.dynamics.com), the script reads a Bearer
  token from control\dvtoken.tmp (written by BayAgent before launching this script).
  Dataverse file columns are downloaded via the chunked API (InitializeFileBlocksDownload
  + DownloadBlock) with CallerObjectId impersonation because S2S tokens cannot access
  file columns directly. The CallerObjectId (Azure AD OID of a licensed Dataverse user)
  is read from agent-config.json or defaults to the operator account.

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
  [int]$DownloadRetries = 3
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

function Get-DataverseToken() {
  # BayAgent writes its current OAuth token here before launching update scripts.
  $tokenFile = Join-Path $BaseDir "control\dvtoken.tmp"
  if (Test-Path -LiteralPath $tokenFile) {
    $tok = (Get-Content -LiteralPath $tokenFile -Raw).Trim()
    Remove-Item -LiteralPath $tokenFile -Force -ErrorAction SilentlyContinue
    if (-not [string]::IsNullOrWhiteSpace($tok)) { return $tok }
  }
  return $null
}

function Test-IsDataverseUrl([string]$url) {
  return ($url -match '\.crm\d*\.dynamics\.com/')
}

function Download-DataverseChunked([string]$url, [string]$outFile, [string]$token) {
  # Parse: https://<org>.crm.dynamics.com/api/data/v9.2/<entitySet>(<id>)/<fileAttr>/$value
  if ($url -notmatch '^(https://[^/]+/api/data/v[\d.]+)/(\w+)\(([0-9a-f-]+)\)/(\w+)/\$value$') {
    throw "Cannot parse Dataverse file URL: $url"
  }
  $baseApi     = $Matches[1]
  $entitySet   = $Matches[2]
  $recordId    = $Matches[3]
  $fileAttr    = $Matches[4]
  $entityName  = $entitySet.TrimEnd('s')
  $entityIdKey = "${entityName}id"

  Write-Log "Chunked download: entity=$entityName record=$recordId attr=$fileAttr"

  # S2S (client_credentials) tokens cannot access file columns directly.
  # Impersonate a licensed Dataverse user via MSCRMCallerID header.
  # Reads callerSystemUserId from agent-config.json or uses default.
  $callerSuid = "2eb983d2-4747-f011-877a-000d3a3bc395"
  try {
    $cfgPath = Join-Path $BaseDir "agent-config.json"
    if (Test-Path -LiteralPath $cfgPath) {
      $cfg = Get-Content -LiteralPath $cfgPath -Raw | ConvertFrom-Json
      $cfgSuid = $cfg.callerSystemUserId
      if (-not [string]::IsNullOrWhiteSpace($cfgSuid)) { $callerSuid = $cfgSuid }
    }
  } catch {}

  $hdrs = @{
    "Authorization"    = "Bearer $token"
    "Accept"           = "application/json"
    "Content-Type"     = "application/json"
    "OData-MaxVersion" = "4.0"
    "OData-Version"    = "4.0"
    "MSCRMCallerID"    = $callerSuid
    "CallerObjectId"   = "f2397a22-2404-4ff7-8e30-f2447e5f607a"
  }
  Write-Log "Impersonation: MSCRMCallerID=$callerSuid CallerObjectId=f2397a22..."

  # Step 1: InitializeFileBlocksDownload
  $initBody = @{
    Target = @{
      "@odata.type" = "Microsoft.Dynamics.CRM.$entityName"
      $entityIdKey  = $recordId
    }
    FileAttributeName = $fileAttr
  } | ConvertTo-Json -Depth 5

  Write-Log "POST $baseApi/InitializeFileBlocksDownload"
  try {
    $initResp = Invoke-RestMethod -Uri "$baseApi/InitializeFileBlocksDownload" `
      -Method POST -Headers $hdrs -Body $initBody
  } catch {
    $ex = $_.Exception
    $statusCode = ""
    $respBody = ""
    if ($ex -is [System.Net.WebException] -and $null -ne $ex.Response) {
      $statusCode = [int]$ex.Response.StatusCode
      $sr = New-Object System.IO.StreamReader($ex.Response.GetResponseStream())
      $respBody = $sr.ReadToEnd()
      $sr.Close()
    }
    Write-Log "InitializeFileBlocksDownload FAILED: status=$statusCode body=$respBody"
    throw
  }
  $fileSize  = $initResp.FileSizeInBytes
  $contToken = $initResp.FileContinuationToken
  Write-Log "InitializeFileBlocksDownload OK -- file=$($initResp.FileName) size=$fileSize"

  # Step 2: DownloadBlock (single block -- fleet packages are well under 4 MB)
  $dlBody = @{
    Offset                = 0
    BlockLength           = $fileSize
    FileContinuationToken = $contToken
  } | ConvertTo-Json -Depth 5

  Write-Log "POST $baseApi/DownloadBlock"
  try {
    $dlResp = Invoke-RestMethod -Uri "$baseApi/DownloadBlock" `
      -Method POST -Headers $hdrs -Body $dlBody
  } catch {
    $ex = $_.Exception
    $statusCode = ""
    $respBody = ""
    if ($ex -is [System.Net.WebException] -and $null -ne $ex.Response) {
      $statusCode = [int]$ex.Response.StatusCode
      $sr = New-Object System.IO.StreamReader($ex.Response.GetResponseStream())
      $respBody = $sr.ReadToEnd()
      $sr.Close()
    }
    Write-Log "DownloadBlock FAILED: status=$statusCode body=$respBody"
    throw
  }

  # Step 3: Decode base64 → write file
  $bytes = [Convert]::FromBase64String($dlResp.Data)
  [IO.File]::WriteAllBytes($outFile, $bytes)
  Write-Log "DownloadBlock OK -- wrote $($bytes.Length) bytes to $outFile"
}

function Download-FileWithRetry([string]$url, [string]$outFile, [int]$retries) {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

  $isDv = Test-IsDataverseUrl $url
  $dvToken = $null
  if ($isDv) {
    $dvToken = Get-DataverseToken
    if (-not $dvToken) {
      throw "Dataverse file download requires OAuth token in control\dvtoken.tmp"
    }
    Write-Log "Dataverse URL detected -- using chunked download API."
  }

  $lastErr = $null
  for ($i = 1; $i -le $retries; $i++) {
    try {
      Write-Log "Downloading (attempt $i/$retries): $url"
      if ($isDv) {
        Download-DataverseChunked -url $url -outFile $outFile -token $dvToken
      } else {
        Invoke-WebRequest -Uri $url -OutFile $outFile -UseBasicParsing -MaximumRedirection 10
      }
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

function Sign-File([string]$path, $cert) {
  if (-not (Test-Path -LiteralPath $path)) { return $false }
  $ext = [IO.Path]::GetExtension($path).ToLowerInvariant()
  if ($ext -notin @(".ps1", ".psm1", ".psd1")) { return $false }

  # Signing modifies file content: do it only after all copying is complete.
  Set-AuthenticodeSignature -FilePath $path -Certificate $cert | Out-Null
  $sig = Get-AuthenticodeSignature -FilePath $path

  if ($sig.Status -ne "Valid") {
    throw "Signature invalid for $path. Status=$($sig.Status) Message=$($sig.StatusMessage)"
  }

  return $true
}

# ------------------ MAIN ------------------

Write-Log "----"
Write-Log "Starting update. Version=$Version Url=$PackageUrl BaseDir=$BaseDir SignAfterInstall=$([bool]$SignAfterInstall) RequestRestart=$([bool]$RequestRestart)"

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

  if (Sign-File -path $relAgentPath -cert $cert) { $signCount++ }

  # Sign any shipped modules/scripts in the release folder too
  $toSign = @(Get-ChildItem -LiteralPath $relDir -Recurse -File |
    Where-Object { $_.Extension -in ".ps1", ".psm1", ".psd1" })

  foreach ($f in $toSign) {
    if ($f.FullName -ieq $relAgentPath) { continue }
    if (Sign-File -path $f.FullName -cert $cert) { $signCount++ }
  }

  # Verify the release agent signature is Valid before touching current
  $sig = Get-AuthenticodeSignature -FilePath $relAgentPath
  if ($sig.Status -ne "Valid") {
    throw "Release BayAgent.ps1 signature invalid ($($sig.Status)): $($sig.StatusMessage)"
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



# SIG # Begin signature block
# MIIFiwYJKoZIhvcNAQcCoIIFfDCCBXgCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUuIFlpkMU7GCwiSDe84tPjR9t
# K16gggMcMIIDGDCCAgCgAwIBAgIQcB7+YhwgR7ZJib3KL4WIcjANBgkqhkiG9w0B
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
# BAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUFifHH7vnlypkUUkmY8mqly57IsMwDQYJ
# KoZIhvcNAQEBBQAEggEAMPL/Q0UZ5s8gq9wlqdMjKxeBqETzzVsGGxPMEETCNWbq
# bnBqs618nVF0JGnMU/SxyifuFeVITc6cUbgbcJlI40YxIeL/T8tjIgEPGWBOorcc
# TDoqpcxiks2ExrwAzPPImDicDkkSOaNzI/cqKx36RgjRizntKCI0Zma29Bkt6rUD
# ay3x3zH3Bi3Ry/zEOxq68ge8wrrdvatGES5k+IDWLMzMW5HmiNvIKfBL5ZBgG4Cs
# 4Gx3mmfk7O56P44gJ4dTQoLc26vT78OyiP6HTGdTqoWfwEYsfLOa1/mKsXqEfVjV
# 8oGYHnPpQ0zRXsyAnMrEf+hf1Rhb/9mOv8sTA5zr6g==
# SIG # End signature block
