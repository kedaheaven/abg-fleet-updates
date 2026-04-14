[CmdletBinding()]
param([switch]$FromAgent)

$ErrorActionPreference = "Stop"

$BaseDir    = "C:\AllBirdies\BayAgent"
$ControlDir = Join-Path $BaseDir "control"
$LogDir     = Join-Path $BaseDir "logs"

$StopFile1  = Join-Path $BaseDir "stop.host"
$StopFile2  = Join-Path $ControlDir "stop.host"
$Rq         = Join-Path $ControlDir "restart.host"
$LogPath    = Join-Path $LogDir ("RestartBayAgent-{0}.log" -f (Get-Date -Format yyyyMMdd))

function Log([string]$msg) {
  $ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  try { Add-Content -Path $LogPath -Value ("$ts $msg") -Encoding UTF8 } catch {}
  Write-Output $msg
}

# Avoid "-or" entirely (PowerShell can misread it as a parameter in some contexts)
$hasStop = $false
if (Test-Path $StopFile1) { $hasStop = $true }
if (Test-Path $StopFile2) { $hasStop = $true }

if ($hasStop) {
  Log "stop.host present; not requesting restart."
  exit 0
}

if (-not (Test-Path $ControlDir)) {
  New-Item -ItemType Directory -Path $ControlDir -Force | Out-Null
}

try {
  $stamp  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  $procId = $PID
  $who    = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

  $content = @(
    "requestedUtc=$stamp"
    "requestedBy=$who"
    "requesterPid=$procId"
    "fromAgent=$FromAgent"
  ) -join "`r`n"

  Set-Content -Path $Rq -Value $content -Encoding ASCII -Force
  Log ("Restart requested (marker written): {0}" -f $Rq)
  exit 0
}
catch {
  Log ("Failed to write restart marker: {0}" -f $_.Exception.Message)
  exit 1
}

# SIG # Begin signature block
# MIIFiwYJKoZIhvcNAQcCoIIFfDCCBXgCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU2zt4Dom0wN12HqmwFK9xYAnP
# 7iGgggMcMIIDGDCCAgCgAwIBAgIQcB7+YhwgR7ZJib3KL4WIcjANBgkqhkiG9w0B
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
# BAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUZDmVl1Ij0oVNJSaXlQSSlv2jeVQwDQYJ
# KoZIhvcNAQEBBQAEggEAoLQ0lAFINUitkoO9wLC6WR5iwsdYJ3aa/SeOMPSuF+nn
# PDEBVfjdQTp4HVrDNJaRrR/tGlX4C9geJy5ZCRuodkATzZTcIUrAq/l+iqaMMBJM
# 17xHeqGLvJeqw5SMtQreW6rElhtyvxlh9hUQ8CEW/Ug+Reb3WPMfZfuYV9lNP1LC
# MCaeC8l+IPJ8ZFwwCJJ7YQEX3xuILHOEQTln56RO/EQ4Ye7ttb4LSwHWZxOFJXWS
# QYcACMIb5vtnqyPU9BB3ZZHsbIweX1uSJIrBbCeJj++OdBF1CJ17bt/SNTjM8GMB
# zXi89VkTZpazlmcUPJ7VKrvNqztTt15rBei1Zky11Q==
# SIG # End signature block
