<#
Update-PromosPack.ps1
- Downloads a promos pack zip (promos.json + promos/ assets)
- Validates SHA256 (optional)
- Validates promos.json parses
- Validates every referenced bg.src under /promos/ exists in the pack
- Mirrors promos/ assets into C:\AllBirdies\SessionDisplay\data\promos\ (deletes old files not in pack)
- Atomically replaces C:\AllBirdies\SessionDisplay\data\promos.json
- Logs to C:\AllBirdies\BayAgent\logs\Update-PromosPack.log

Run via BayCommand StartProcess.
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$PackageUrl,
  [string]$Sha256 = "",

  [string]$SessionDisplayDir = "C:\AllBirdies\SessionDisplay",
  [string]$LogPath = "C:\AllBirdies\BayAgent\logs\Update-PromosPack.log"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Ensure-Dir([string]$p) {
  if (-not (Test-Path -LiteralPath $p)) {
    New-Item -ItemType Directory -Path $p -Force | Out-Null
  }
}

function Write-Log([string]$msg) {
  Ensure-Dir (Split-Path $LogPath -Parent)
  $line = "{0} {1}" -f (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"), $msg
  Add-Content -Path $LogPath -Value $line -Encoding UTF8
}

function Get-Sha256Lower([string]$path) {
  return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Invoke-RoboCopyMirror([string]$src, [string]$dst) {
  Ensure-Dir $dst
  # /MIR mirrors and deletes dest files not present in src
  $args = @($src, $dst, "/MIR", "/R:2", "/W:1", "/NFL", "/NDL", "/NJH", "/NJS", "/NP")
  $p = Start-Process -FilePath "robocopy.exe" -ArgumentList $args -Wait -PassThru -NoNewWindow
  # Robocopy exit codes: 0-7 are OK, 8+ is failure
  if ($p.ExitCode -ge 8) { throw "Robocopy /MIR failed with exit code $($p.ExitCode)" }
}

function Normalize-PromoAssetRelPath([string]$src) {
  if ([string]::IsNullOrWhiteSpace($src)) { return $null }

  # We expect bg.src like "../data/promos/noonflight.jpg" or "promos/noonflight.jpg"
  # Extract everything after "/promos/" or "promos/" and normalize to Windows relative path
  $s = $src.Trim()

  # Disallow obvious traversal
  if ($s -match "\.\.[\\/]" -and $s -notmatch "^\.\.[\\/]data[\\/]promos[\\/]") {
    throw "bg.src contains unsupported path traversal: $src"
  }

  $rel = $null

  $m = [regex]::Match($s, "(?i)(?:^|[\\/])promos[\\/](.+)$")
  if ($m.Success) {
    $rel = $m.Groups[1].Value
  } else {
    return $null
  }

  # Convert URL slashes to Windows slashes
  $rel = $rel -replace "/", "\"

  # Final hardening: no drive letters, no rooted paths
  if ([System.IO.Path]::IsPathRooted($rel)) {
    throw "bg.src resolves to a rooted path (not allowed): $src"
  }
  if ($rel -match "^[A-Za-z]:") {
    throw "bg.src contains a drive path (not allowed): $src"
  }

  return $rel
}

Write-Log "----"
Write-Log "Starting promos pack update. Url=$PackageUrl ShaProvided=$([bool](-not [string]::IsNullOrWhiteSpace($Sha256)))"

# Target paths
$dataDir    = Join-Path $SessionDisplayDir "data"
$promosDir  = Join-Path $dataDir "promos"
$destJson   = Join-Path $dataDir "promos.json"

Ensure-Dir $dataDir
Ensure-Dir $promosDir
Ensure-Dir (Split-Path $LogPath -Parent)

# Staging
$staging   = Join-Path $env:TEMP ("abg-promos-staging-{0}" -f ([Guid]::NewGuid().ToString("N")))
$zipPath   = Join-Path $staging "PromosPack.zip"
$expandDir = Join-Path $staging "expand"
Ensure-Dir $staging
Ensure-Dir $expandDir

try {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

  Write-Log "Downloading zip..."
  Invoke-WebRequest -Uri $PackageUrl -OutFile $zipPath -UseBasicParsing

  if (-not [string]::IsNullOrWhiteSpace($Sha256)) {
    $actual   = Get-Sha256Lower $zipPath
    $expected = $Sha256.ToLowerInvariant().Replace(" ", "")
    Write-Log "SHA expected=$expected actual=$actual"
    if ($actual -ne $expected) { throw "SHA256 mismatch. Expected $expected, got $actual" }
  } else {
    Write-Log "SHA256 not provided (skipping hash validation)."
  }

  Write-Log "Expanding zip..."
  Expand-Archive -LiteralPath $zipPath -DestinationPath $expandDir -Force

  # Detect content root (support single top-level folder)
  $contentRoot = $expandDir
  $children = @(Get-ChildItem -LiteralPath $expandDir)
  if ($children.Count -eq 1 -and $children[0].PSIsContainer) { $contentRoot = $children[0].FullName }

  $packJson = Join-Path $contentRoot "promos.json"
  if (-not (Test-Path -LiteralPath $packJson)) { throw "promos.json not found in pack root." }

  $packPromosDir = Join-Path $contentRoot "promos"
  if (-not (Test-Path -LiteralPath $packPromosDir)) {
    throw "promos/ folder not found in pack. For pruning behavior, promos/ must be present."
  }

  Write-Log "Validating promos.json parses..."
  $raw = Get-Content -LiteralPath $packJson -Raw -Encoding UTF8
  $obj = $raw | ConvertFrom-Json

  # Extract promos array (support either {promos:[...]} or [...] directly)
  $promos = $null
  if ($obj -is [System.Array]) { $promos = $obj }
  elseif ($null -ne $obj.promos) { $promos = $obj.promos }
  else { throw "promos.json must be an array or an object with a 'promos' array." }

  # Build list of referenced bg assets (relative paths under promos/)
  $referenced = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)

  foreach ($p in $promos) {
    if ($null -eq $p) { continue }
    if ($null -eq $p.bg) { continue }
    $src = $p.bg.src
    $rel = Normalize-PromoAssetRelPath $src
    if ($null -ne $rel -and $rel.Trim() -ne "") {
      [void]$referenced.Add($rel)
    }
  }

  # Safety check: every referenced asset must exist in the pack promos/ folder
  foreach ($rel in $referenced) {
    $candidate = Join-Path $packPromosDir $rel
    if (-not (Test-Path -LiteralPath $candidate)) {
      throw "Referenced promo image missing from pack: '$rel' (expected at $candidate). Aborting to prevent deletions."
    }
  }

  Write-Log ("Referenced promo images in new pack: {0}" -f $referenced.Count)

  # Mirror pack assets -> destination (this deletes old/unlisted files)
  Write-Log "Mirroring promo assets to data\promos (deleting removed files)..."
  Invoke-RoboCopyMirror $packPromosDir $promosDir

  # Atomic replace promos.json AFTER assets are in place
  Write-Log "Updating promos.json..."
  $tmpJson = Join-Path $dataDir ("promos.json.tmp.{0}" -f ([Guid]::NewGuid().ToString("N")))
  Set-Content -LiteralPath $tmpJson -Value $raw -Encoding UTF8
  Move-Item -LiteralPath $tmpJson -Destination $destJson -Force

  Write-Log "OK: Promos pack installed."
  Write-Output "OK: Promos pack installed."
}
finally {
  try { Remove-Item -LiteralPath $staging -Recurse -Force } catch {}
}
# SIG # Begin signature block
# MIIb7wYJKoZIhvcNAQcCoIIb4DCCG9wCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUvPaXRDCHvQabgm8ehuj1LCuL
# ES2gghZWMIIDGDCCAgCgAwIBAgIQcB7+YhwgR7ZJib3KL4WIcjANBgkqhkiG9w0B
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
# 0SPAugVCPD0VTyDtOavtPO1ZmA1nwRA36FKC8ZqWUF2mrzCCBY0wggR1oAMCAQIC
# EA6bGI750C3n79tQ4ghAGFowDQYJKoZIhvcNAQEMBQAwZTELMAkGA1UEBhMCVVMx
# FTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNv
# bTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNzdXJlZCBJRCBSb290IENBMB4XDTIyMDgw
# MTAwMDAwMFoXDTMxMTEwOTIzNTk1OVowYjELMAkGA1UEBhMCVVMxFTATBgNVBAoT
# DERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UE
# AxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAv+aQc2jeu+RdSjwwIjBpM+zCpyUuySE98orYWcLhKac9WKt2
# ms2uexuEDcQwH/MbpDgW61bGl20dq7J58soR0uRf1gU8Ug9SH8aeFaV+vp+pVxZZ
# VXKvaJNwwrK6dZlqczKU0RBEEC7fgvMHhOZ0O21x4i0MG+4g1ckgHWMpLc7sXk7I
# k/ghYZs06wXGXuxbGrzryc/NrDRAX7F6Zu53yEioZldXn1RYjgwrt0+nMNlW7sp7
# XeOtyU9e5TXnMcvak17cjo+A2raRmECQecN4x7axxLVqGDgDEI3Y1DekLgV9iPWC
# PhCRcKtVgkEy19sEcypukQF8IUzUvK4bA3VdeGbZOjFEmjNAvwjXWkmkwuapoGfd
# pCe8oU85tRFYF/ckXEaPZPfBaYh2mHY9WV1CdoeJl2l6SPDgohIbZpp0yt5LHucO
# Y67m1O+SkjqePdwA5EUlibaaRBkrfsCUtNJhbesz2cXfSwQAzH0clcOP9yGyshG3
# u3/y1YxwLEFgqrFjGESVGnZifvaAsPvoZKYz0YkH4b235kOkGLimdwHhD5QMIR2y
# VCkliWzlDlJRR3S+Jqy2QXXeeqxfjT/JvNNBERJb5RBQ6zHFynIWIgnffEx1P2Ps
# IV/EIFFrb7GrhotPwtZFX50g/KEexcCPorF+CiaZ9eRpL5gdLfXZqbId5RsCAwEA
# AaOCATowggE2MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFOzX44LScV1kTN8u
# Zz/nupiuHA9PMB8GA1UdIwQYMBaAFEXroq/0ksuCMS1Ri6enIZ3zbcgPMA4GA1Ud
# DwEB/wQEAwIBhjB5BggrBgEFBQcBAQRtMGswJAYIKwYBBQUHMAGGGGh0dHA6Ly9v
# Y3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3aHR0cDovL2NhY2VydHMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNydDBFBgNVHR8EPjA8
# MDqgOKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVk
# SURSb290Q0EuY3JsMBEGA1UdIAQKMAgwBgYEVR0gADANBgkqhkiG9w0BAQwFAAOC
# AQEAcKC/Q1xV5zhfoKN0Gz22Ftf3v1cHvZqsoYcs7IVeqRq7IviHGmlUIu2kiHdt
# vRoU9BNKei8ttzjv9P+Aufih9/Jy3iS8UgPITtAq3votVs/59PesMHqai7Je1M/R
# Q0SbQyHrlnKhSLSZy51PpwYDE3cnRNTnf+hZqPC/Lwum6fI0POz3A8eHqNJMQBk1
# RmppVLC4oVaO7KTVPeix3P0c2PR3WlxUjG/voVA9/HYJaISfb8rbII01YBwCA8sg
# sKxYoA5AY8WYIsGyWfVVa88nq2x2zm8jLfR+cWojayL/ErhULSd+2DrZ8LaHlv1b
# 0VysGMNNn3O3AamfV6peKOK5lDCCBrQwggScoAMCAQICEA3HrFcF/yGZLkBDIgw6
# SYYwDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lD
# ZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGln
# aUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTI1MDUwNzAwMDAwMFoXDTM4MDExNDIz
# NTk1OVowaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2
# IFNIQTI1NiAyMDI1IENBMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# ALR4MdMKmEFyvjxGwBysddujRmh0tFEXnU2tjQ2UtZmWgyxU7UNqEY81FzJsQqr5
# G7A6c+Gh/qm8Xi4aPCOo2N8S9SLrC6Kbltqn7SWCWgzbNfiR+2fkHUiljNOqnIVD
# /gG3SYDEAd4dg2dDGpeZGKe+42DFUF0mR/vtLa4+gKPsYfwEu7EEbkC9+0F2w4QJ
# LVSTEG8yAR2CQWIM1iI5PHg62IVwxKSpO0XaF9DPfNBKS7Zazch8NF5vp7eaZ2CV
# NxpqumzTCNSOxm+SAWSuIr21Qomb+zzQWKhxKTVVgtmUPAW35xUUFREmDrMxSNlr
# /NsJyUXzdtFUUt4aS4CEeIY8y9IaaGBpPNXKFifinT7zL2gdFpBP9qh8SdLnEut/
# GcalNeJQ55IuwnKCgs+nrpuQNfVmUB5KlCX3ZA4x5HHKS+rqBvKWxdCyQEEGcbLe
# 1b8Aw4wJkhU1JrPsFfxW1gaou30yZ46t4Y9F20HHfIY4/6vHespYMQmUiote8lad
# jS/nJ0+k6MvqzfpzPDOy5y6gqztiT96Fv/9bH7mQyogxG9QEPHrPV6/7umw052Ak
# yiLA6tQbZl1KhBtTasySkuJDpsZGKdlsjg4u70EwgWbVRSX1Wd4+zoFpp4Ra+MlK
# M2baoD6x0VR4RjSpWM8o5a6D8bpfm4CLKczsG7ZrIGNTAgMBAAGjggFdMIIBWTAS
# BgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTvb1NK6eQGfHrK4pBW9i/USezL
# TjAfBgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNVHQ8BAf8EBAMC
# AYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYBBQUHAQEEazBpMCQGCCsGAQUF
# BzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6
# Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3J0
# MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdp
# Q2VydFRydXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCG
# SAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEAF877FoAc/gc9EXZxML2+C8i1NKZ/
# zdCHxYgaMH9Pw5tcBnPw6O6FTGNpoV2V4wzSUGvI9NAzaoQk97frPBtIj+ZLzdp+
# yXdhOP4hCFATuNT+ReOPK0mCefSG+tXqGpYZ3essBS3q8nL2UwM+NMvEuBd/2vmd
# YxDCvwzJv2sRUoKEfJ+nN57mQfQXwcAEGCvRR2qKtntujB71WPYAgwPyWLKu6Rna
# ID/B0ba2H3LUiwDRAXx1Neq9ydOal95CHfmTnM4I+ZI2rVQfjXQA1WSjjf4J2a7j
# LzWGNqNX+DF0SQzHU0pTi4dBwp9nEC8EAqoxW6q17r0z0noDjs6+BFo+z7bKSBwZ
# XTRNivYuve3L2oiKNqetRHdqfMTCW/NmKLJ9M+MtucVGyOxiDf06VXxyKkOirv6o
# 02OoXN4bFzK0vlNMsvhlqgF2puE6FndlENSmE+9JGYxOGLS/D284NHNboDGcmWXf
# wXRy4kbu4QFhOm0xJuF2EZAOk5eCkhSxZON3rGlHqhpB/8MluDezooIs8CVnrpHM
# iD2wL40mm53+/j7tFaxYKIqL0Q4ssd8xHZnIn/7GELH3IdvG2XlM9q7WP/UwgOkw
# /HQtyRN62JK4S1C8uw3PdBunvAZapsiI5YKdvlarEvf8EA+8hcpSM9LHJmyrxaFt
# oza2zNaQ9k+5t1wwggbtMIIE1aADAgECAhAKgO8YS43xBYLRxHanlXRoMA0GCSqG
# SIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5j
# LjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNB
# NDA5NiBTSEEyNTYgMjAyNSBDQTEwHhcNMjUwNjA0MDAwMDAwWhcNMzYwOTAzMjM1
# OTU5WjBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5
# BgNVBAMTMkRpZ2lDZXJ0IFNIQTI1NiBSU0E0MDk2IFRpbWVzdGFtcCBSZXNwb25k
# ZXIgMjAyNSAxMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0EasLRLG
# ntDqrmBWsytXum9R/4ZwCgHfyjfMGUIwYzKomd8U1nH7C8Dr0cVMF3BsfAFI54um
# 8+dnxk36+jx0Tb+k+87H9WPxNyFPJIDZHhAqlUPt281mHrBbZHqRK71Em3/hCGC5
# KyyneqiZ7syvFXJ9A72wzHpkBaMUNg7MOLxI6E9RaUueHTQKWXymOtRwJXcrcTTP
# PT2V1D/+cFllESviH8YjoPFvZSjKs3SKO1QNUdFd2adw44wDcKgH+JRJE5Qg0NP3
# yiSyi5MxgU6cehGHr7zou1znOM8odbkqoK+lJ25LCHBSai25CFyD23DZgPfDrJJJ
# K77epTwMP6eKA0kWa3osAe8fcpK40uhktzUd/Yk0xUvhDU6lvJukx7jphx40DQt8
# 2yepyekl4i0r8OEps/FNO4ahfvAk12hE5FVs9HVVWcO5J4dVmVzix4A77p3awLbr
# 89A90/nWGjXMGn7FQhmSlIUDy9Z2hSgctaepZTd0ILIUbWuhKuAeNIeWrzHKYueM
# JtItnj2Q+aTyLLKLM0MheP/9w6CtjuuVHJOVoIJ/DtpJRE7Ce7vMRHoRon4CWIvu
# iNN1Lk9Y+xZ66lazs2kKFSTnnkrT3pXWETTJkhd76CIDBbTRofOsNyEhzZtCGmnQ
# igpFHti58CSmvEyJcAlDVcKacJ+A9/z7eacCAwEAAaOCAZUwggGRMAwGA1UdEwEB
# /wQCMAAwHQYDVR0OBBYEFOQ7/PIx7f391/ORcWMZUEPPYYzoMB8GA1UdIwQYMBaA
# FO9vU0rp5AZ8esrikFb2L9RJ7MtOMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8E
# DDAKBggrBgEFBQcDCDCBlQYIKwYBBQUHAQEEgYgwgYUwJAYIKwYBBQUHMAGGGGh0
# dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBdBggrBgEFBQcwAoZRaHR0cDovL2NhY2Vy
# dHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5nUlNB
# NDA5NlNIQTI1NjIwMjVDQTEuY3J0MF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly9j
# cmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JT
# QTQwOTZTSEEyNTYyMDI1Q0ExLmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglg
# hkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBAGUqrfEcJwS5rmBB7NEIRJ5jQHIh
# +OT2Ik/bNYulCrVvhREafBYF0RkP2AGr181o2YWPoSHz9iZEN/FPsLSTwVQWo2H6
# 2yGBvg7ouCODwrx6ULj6hYKqdT8wv2UV+Kbz/3ImZlJ7YXwBD9R0oU62PtgxOao8
# 72bOySCILdBghQ/ZLcdC8cbUUO75ZSpbh1oipOhcUT8lD8QAGB9lctZTTOJM3pHf
# KBAEcxQFoHlt2s9sXoxFizTeHihsQyfFg5fxUFEp7W42fNBVN4ueLaceRf9Cq9ec
# 1v5iQMWTFQa0xNqItH3CPFTG7aEQJmmrJTV3Qhtfparz+BW60OiMEgV5GWoBy4RV
# PRwqxv7Mk0Sy4QHs7v9y69NBqycz0BZwhB9WOfOu/CIJnzkQTwtSSpGGhLdjnQ4e
# BpjtP+XB3pQCtv4E5UCSDag6+iX8MmB10nfldPF9SVD7weCC3yXZi/uuhqdwkgVx
# uiMFzGVFwYbQsiGnoa9F5AaAyBjFBtXVLcKtapnMG3VH3EmAp/jsJ3FVF3+d1SVD
# TmjFjLbNFZUWMXuZyvgLfgyPehwJVxwC+UpX2MSey2ueIu9THFVkT+um1vshETaW
# yQo8gmBto/m3acaP9QsuLj3FNwFlTxq25+T4QwX9xa6ILs84ZPvmpovq90K8eWyG
# 2N01c4IhSOxqt81nMYIFAzCCBP8CAQEwODAkMSIwIAYDVQQDDBlBQkcgQmF5QWdl
# bnQgQ29kZSBTaWduaW5nAhBwHv5iHCBHtkmJvcovhYhyMAkGBSsOAwIaBQCgeDAY
# BgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3
# AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEW
# BBTebG9zmaSWMh/06xsaPPi6vOcVTDANBgkqhkiG9w0BAQEFAASCAQBkPykO3Jx6
# Mrn4gC83WDBTIgBu9ZMPoYiSyv+iPeZ/0Dt+3ACi6QJokW+9P5RgvQoGtlzbkSBW
# b32qTDF8lguJYke9MBeg+kETaSDSkMH3YaXcXMQpsPLsSKyS3tI2TDo6KSP8U/EG
# m2c9bp1liXmIPcOPY/C0zkNrMuzijy8yim7bSfLzLEUZ+l68pQBDqOAmicDQSM7r
# rN9gURSyqhOG8Oyoy81oW/uojX5AGmJaQ+d7cXNqmKfPKxNlOMdxxnnHKIdRgKHP
# G0CuhJL06hLiQavufn9FL0XKTs2DJ3zoZRtFkpyBc7gyIeW4i1WOV+ZPb2d2GiDs
# Sqz61FDN+UVWoYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMPAgEBMH0waTELMAkG
# A1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdp
# Q2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1
# IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3
# DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI2MDExODExNTc1OVow
# LwYJKoZIhvcNAQkEMSIEIIvPEtx2mzPszFRyjdyVuzNaNjIdZqQNRVPQt2Fnakuh
# MA0GCSqGSIb3DQEBAQUABIICAEslzZw7d7ic8wP0l2zJQhVSI+xiWJMM8pFPCr7M
# +Uq8pW3bMB32JGjMFQchjbirMDuD1pOUWbqribEKWsQCMGwOgONqRvW6hUCBe5hn
# FC54vd9ar2WsVrtIifsY/wBsWR8DnRjV24KF6mwcb2AzDfKxP5+cEThPWcXLQpwz
# q5EY00IMAd6s9kgW2wfJWZJMViG8hzHLD6yhfG0B8mLEiqEVAbGjaroe0Q6aYPRD
# zd9TJNAKML8RuabsLvGpnNjv6ZJ+QKmv9wXBA/z55gYk4Q8u30MwDmDliuQCTFOF
# 08ebEDc/02QzwOdxlez9kIaDs7+l+luyVWNq3tVzYdTh90rJ1JROPtK1jpnhxk0m
# k5sGkahExT0AdR+7+DII1qn9Gx0QPXUfjSKkFF/Wbn5/bceZIIR4nyxOp0B8kWUB
# LINift7C2/HOCAfuGNxLDCz7+Vnw+AJXSIBkSZ8MdNhGJ6ihR6sc+T8AEeNAfCiB
# rKXIvCRD3GjMa2q182azlnMfHuDjikuWKdmNrRHdJS2HL3X8GTdbu4BWbeyhPWwX
# SNhul4i8IVC4WuSwZtR2Sb1MJkmLAyuHLwKsgENF461O3iZAHcLA8erbZ0/pGPrq
# MczsVSKptpy8iiR4Dfr2fqDlskvCwYoV9IyT3OHVHC3aBSKbwlz6WUcPWxcbXn2L
# w5ny
# SIG # End signature block
