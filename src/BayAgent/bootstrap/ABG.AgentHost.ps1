<#
ABG.AgentHost.ps1 (Step 7.2.1)
- Single, stable entrypoint launched by Scheduled Task: \ABG Bay Agent (Run as BayKiosk)
- Starts and supervises BayAgent.ps1 from C:\AllBirdies\BayAgent\current
- IMPORTANT for AllSigned: does NOT use -ExecutionPolicy Bypass.

Hardening in this version:
- Single-instance lock (mutex) for AgentHost itself
- Pre-start cleanup: kills orphan BayAgent instances before launching a new one
- Writes structured logs to C:\AllBirdies\BayAgent\logs\AgentHost-YYYYMMDD.log
#>

[CmdletBinding()]
param(
  [switch]$Once
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$BaseDir = "C:\AllBirdies\BayAgent"
$LogDir  = Join-Path $BaseDir "logs"
$StopFile = Join-Path $BaseDir "stop.host"

if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Force -Path $LogDir | Out-Null }
$LogFile = Join-Path $LogDir ("AgentHost-{0}.log" -f (Get-Date).ToString("yyyyMMdd"))

function Write-HostLog([string]$msg, [ValidateSet("DEBUG","INFO","WARN","ERROR")] [string]$level="INFO") {
  $ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  $line = "$ts [$level] $msg"
  Write-Host $line
  try { Add-Content -Path $LogFile -Value $line } catch {}
}

# -------------------------
# Single-instance mutex
# -------------------------
$mutex = $null
$createdNew = $false
try {
  $mutex = New-Object System.Threading.Mutex($true, "Global\ABG.AgentHost", [ref]$createdNew)
  if (-not $createdNew) {
    Write-HostLog "Another AgentHost instance is already running. Exiting." "WARN"
    exit 0
  }
} catch {
  Write-HostLog "Failed to create AgentHost mutex (continuing). $($_.Exception.Message)" "WARN"
}

# -------------------------
# Helpers
# -------------------------
function Get-PSProcessesByCmdLike([string]$pattern) {
  Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
    Where-Object { $_.CommandLine -and $_.CommandLine -like $pattern }
}

function Stop-OrphanBayAgents {
  # Match any BayAgent.ps1 running from current or releases
  $procs = @(Get-PSProcessesByCmdLike "*\AllBirdies\BayAgent\*\BayAgent.ps1*")
  if ($procs.Count -gt 0) {
    Write-HostLog ("Found {0} BayAgent process(es) already running. Killing before launch to prevent duplicates." -f $procs.Count) "WARN"
    foreach ($p in $procs) {
      try { Stop-Process -Id $p.ProcessId -Force } catch {}
    }
    Start-Sleep -Milliseconds 300
  }
}

# -------------------------
# Main loop
# -------------------------
try {
  Write-HostLog "AgentHost starting. Once=$Once BaseDir=$BaseDir PID=$PID" "INFO"

  if (Test-Path $StopFile) {
    Write-HostLog "stop.host present; refusing to start BayAgent. Remove $StopFile to resume." "WARN"
    exit 0
  }

  $AgentPath = Join-Path $BaseDir "current\BayAgent.ps1"
  if (!(Test-Path $AgentPath)) { throw "AgentPath not found: $AgentPath" }

  $psExe = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
  $delay = 5
  $MaxRestartDelaySeconds = 60

  while ($true) {
    if (Test-Path $StopFile) {
      Write-HostLog "stop.host present; exiting AgentHost." "WARN"
      break
    }

    # Prevent duplicates if AgentHost was restarted while BayAgent survived
    Stop-OrphanBayAgents

    $arg = "-NoProfile -WindowStyle Minimized -File `"$AgentPath`""
    Write-HostLog "Starting agent: $psExe $arg" "INFO"

    $p = Start-Process -FilePath $psExe -ArgumentList $arg -PassThru -WindowStyle Minimized
    Write-HostLog "Agent started. pid=$($p.Id)" "INFO"

    Wait-Process -Id $p.Id
    $exitCode = $p.ExitCode
    Write-HostLog "Agent exited. pid=$($p.Id) exitCode=$exitCode" "WARN"

    if ($Once) { break }

    Write-HostLog "Restarting agent after $delay seconds..." "INFO"
    Start-Sleep -Seconds $delay
    $delay = [Math]::Min($delay * 2, $MaxRestartDelaySeconds)
  }

  Write-HostLog "AgentHost exiting." "INFO"
  exit 0
}
catch {
  Write-HostLog ("AgentHost fatal: {0}" -f $_.Exception.Message) "ERROR"
  exit 1
}
finally {
  try {
    if ($mutex) {
      if ($createdNew) { $mutex.ReleaseMutex() | Out-Null }
      $mutex.Dispose()
    }
  } catch {}
}

# SIG # Begin signature block
# MIIFiwYJKoZIhvcNAQcCoIIFfDCCBXgCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUr9ajnNViBF8sEy7mhEwZdnRh
# kaGgggMcMIIDGDCCAgCgAwIBAgIQcB7+YhwgR7ZJib3KL4WIcjANBgkqhkiG9w0B
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
# BAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUnOOR4auTaSyeM9oT/F4JWi5yNZ4wDQYJ
# KoZIhvcNAQEBBQAEggEAkhzgPWTtWRnEci5RkE3zDuKti6SiX2RFMMYUQG5IQ/M7
# /j8HglPCmoLDwaiBXG/KFoG/4OfCjpBxmV4tWov29y6SNtLWZ32v+HY1YL0UIUhy
# hYSEJpIDlG1tdfUZ6or/Gs+khMiPzUr7sYOqc8l58vmksT2AS2G9TNDk4Ea9OKDy
# vkSgPD4t5xVsJbL/hrdZ1o5SB5gkluI1vvvNCKE1eNB4Nu/gtapjOU7190OF89nx
# qJnk2EGxZB53SyOrEO/RoJEXVUsg+cwT1z3ZX/B8wL7Y+G0IGAY62i3obwEQXhtW
# 1wSiKEH3Pa42twoNjL1MV8NSKjKS64hihp6qehZqaQ==
# SIG # End signature block
