<#
ABG DPAPI Secret Setup (LocalMachine) - v2
- Prompts for an Entra app client secret and writes it encrypted with DPAPI LocalMachine scope.
- Locks ACLs on the secrets folder + file (best-effort).

Usage:
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\ABG.SetClientSecretDpapi.ps1 `
    -OutPath "C:\AllBirdies\BayAgent\secrets\clientsecret.dpapi" `
    -AgentAccount ".\BayKiosk"
#>

param(
    [Parameter(Mandatory=$true)][string]$OutPath,
    # Optional: the Windows account your agent runs as (for ACLs), e.g. ".\BayKiosk" or "DOMAIN\BayKiosk"
    [string]$AgentAccount = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Ensure DPAPI types are available (ProtectedData is in System.Security)
try { Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue } catch {}

$dir = Split-Path $OutPath -Parent
if (!(Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }

$secure = Read-Host "Enter Entra app client secret" -AsSecureString
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try { $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }

$bytes = [Text.Encoding]::UTF8.GetBytes($plain)

# DPAPI encrypt (LocalMachine)
$enc = [System.Security.Cryptography.ProtectedData]::Protect(
    $bytes,
    $null,
    [System.Security.Cryptography.DataProtectionScope]::LocalMachine
)

[IO.File]::WriteAllBytes($OutPath, $enc)

Write-Host "Wrote DPAPI secret file: $OutPath"

# Best-effort ACL hardening
try {
    & icacls $dir /inheritance:r | Out-Null
    & icacls $dir /grant "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null
    if ($AgentAccount -and $AgentAccount.Trim().Length -gt 0) {
        $grantDir = ("{0}:(OI)(CI)RX" -f $AgentAccount)
        & icacls $dir /grant $grantDir | Out-Null
    }

    & icacls $OutPath /inheritance:r | Out-Null
    & icacls $OutPath /grant "SYSTEM:F" "Administrators:F" | Out-Null
    if ($AgentAccount -and $AgentAccount.Trim().Length -gt 0) {
        $grantFile = ("{0}:R" -f $AgentAccount)
        & icacls $OutPath /grant $grantFile | Out-Null
    }

    Write-Host "ACLs applied (verify with icacls)."
} catch {
    Write-Warning "ACL hardening step failed: $($_.Exception.Message)"
    Write-Warning "You should manually lock ACLs on secrets folder and file."
}
