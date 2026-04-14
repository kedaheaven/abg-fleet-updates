<#
ABG.RotateClientSecretDpapiAndTest.ps1
- Prompts for an Entra App client secret VALUE (SecureString)
- Writes/overwrites a DPAPI(LocalMachine) encrypted secret file
- Optionally applies ACL hardening
- Immediately tests token acquisition using the just-written DPAPI file

Run this in an *elevated* PowerShell (Run as Administrator) if you want ACL hardening and to overwrite locked-down files.

Example:
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\ABG.RotateClientSecretDpapiAndTest.ps1 `
    -TenantId "cc551e6a-be6a-42d2-add4-231f5891a179" `
    -ClientId "0e77dbf6-499d-434c-acfc-b276bc439c38" `
    -OrgUrl "https://builds-apps-dev.crm.dynamics.com" `
    -OutPath "C:\AllBirdies\BayAgent\secrets\clientsecret.dpapi" `
    -AgentAccount "BAY1KIOSK\BayKiosk"

#>

param(
    [Parameter(Mandatory=$true)][string]$TenantId,
    [Parameter(Mandatory=$true)][string]$ClientId,
    [Parameter(Mandatory=$true)][string]$OrgUrl,
    [Parameter(Mandatory=$true)][string]$OutPath,
    [string]$AgentAccount = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

try { Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue } catch {}

function Test-IsElevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Normalize-Account([string]$acct) {
    if ([string]::IsNullOrWhiteSpace($acct)) { return "" }
    $acct = $acct.Trim()
    if ($acct.StartsWith(".\")) { return "$env:COMPUTERNAME\" + $acct.Substring(2) }
    return $acct
}

function Assert-Account-Resolvable([string]$acct) {
    if ([string]::IsNullOrWhiteSpace($acct)) { return }
    try {
        $nt = New-Object System.Security.Principal.NTAccount($acct)
        $null = $nt.Translate([System.Security.Principal.SecurityIdentifier])
        return $true
    } catch {
        throw "AgentAccount '$acct' was not found on this machine/domain. Use COMPUTERNAME\Username for local users."
    }
}

function Read-SecretSecure([string]$prompt) {
    $sec = Read-Host $prompt -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
    try { return ([Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)).Trim() }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Write-DpapiFile([string]$path, [string]$plain) {
    $bytes = [Text.Encoding]::UTF8.GetBytes($plain)
    $enc = [System.Security.Cryptography.ProtectedData]::Protect(
        $bytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine
    )
    [IO.File]::WriteAllBytes($path, $enc)
}

function Read-DpapiFile([string]$path) {
    $enc = [IO.File]::ReadAllBytes($path)
    $bytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $enc, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine
    )
    return ([Text.Encoding]::UTF8.GetString($bytes)).Trim()
}

function Harden-Acls([string]$dir, [string]$file, [string]$acct) {
    $acct = Normalize-Account $acct
    if (-not [string]::IsNullOrWhiteSpace($acct)) { Assert-Account-Resolvable $acct | Out-Null }

    if (-not (Test-IsElevated)) {
        Write-Warning "Not elevated; skipping ACL hardening. (Run PowerShell as Administrator.)"
        return
    }

    & icacls $dir /inheritance:r | Out-Null
    & icacls $dir /grant "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null
    if (-not [string]::IsNullOrWhiteSpace($acct)) {
        & icacls $dir /grant ("{0}:(OI)(CI)RX" -f $acct) | Out-Null
    }

    & icacls $file /inheritance:r | Out-Null
    & icacls $file /grant "SYSTEM:F" "Administrators:F" | Out-Null
    if (-not [string]::IsNullOrWhiteSpace($acct)) {
        & icacls $file /grant ("{0}:R" -f $acct) | Out-Null
    }
}

function Test-Token([string]$tenantId, [string]$clientId, [string]$orgUrl, [string]$secret) {
    $tokenUrl = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
    $body = @{
        client_id     = $clientId
        client_secret = $secret
        grant_type    = "client_credentials"
        scope         = "$orgUrl/.default"
    }

    try {
        $r = Invoke-RestMethod -Method Post -Uri $tokenUrl -ContentType "application/x-www-form-urlencoded" -Body $body -TimeoutSec 30
        Write-Host ("TOKEN OK ✅  token_type={0} expires_in={1}" -f $r.token_type, $r.expires_in)
        return $true
    } catch {
        Write-Host "TOKEN FAIL ❌"
        Write-Host $_.Exception.Message
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) { Write-Host $_.ErrorDetails.Message }
        return $false
    }
}

# ---- Main ----
$dir = Split-Path $OutPath -Parent
if (!(Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }

$AgentAccount = Normalize-Account $AgentAccount

$plain = Read-SecretSecure "Paste NEW client secret VALUE"
Write-DpapiFile -path $OutPath -plain $plain
Write-Host "Wrote DPAPI secret file: $OutPath"

# Try to harden ACLs (safe no-op if not elevated)
Harden-Acls -dir $dir -file $OutPath -acct $AgentAccount

# Read back and test immediately (no secret output)
$roundTrip = Read-DpapiFile -path $OutPath
Write-Host ("Read-back length={0}" -f $roundTrip.Length)

$ok = Test-Token -tenantId $TenantId -clientId $ClientId -orgUrl $OrgUrl -secret $roundTrip
if (-not $ok) { exit 1 }
