<#
Setup-BayPC.ps1
Bay PC provisioning wrapper for new bay PCs.

Wraps ABG-Day0-Setup.ps1 with pre-flight checks, kiosk user creation,
auto-login, Edge kiosk mode, Windows lockdown, and verification.

Run as Administrator on the target bay PC.

Example:
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Setup-BayPC.ps1 `
    -BayNumber 2

Notes:
  - Idempotent: safe to run multiple times on the same PC
  - Day0 is called with the src/BayAgent/ prefix for GitHub raw URLs
  - DPAPI secret must be set separately via ABG.SetClientSecretDpapi.ps1
  - ASCII-only comments (no em-dashes) for AllSigned compatibility
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [int]$BayNumber,

  [string]$AllBirdiesRoot = "C:\AllBirdies",

  # Day0 control
  [switch]$SkipDay0,
  [switch]$SkipKioskSetup,
  [switch]$SkipLockdown,
  [switch]$SkipReboot,

  # Day0 pass-through
  [string]$FleetRawBaseUrl = "https://raw.githubusercontent.com/kedaheaven/abg-fleet-updates/main/src/BayAgent",
  [string]$BayKioskUser = "BayKiosk",

  # Dataverse registration (optional, passed to Day0)
  [switch]$RegisterConfigItems,
  [string]$EnvironmentUrl = "https://builds-apps-dev.crm.dynamics.com",
  [string]$TenantId = "cc551e6a-be6a-42d2-add4-231f5891a179",
  [string]$ClientId = "0e77dbf6-499d-434c-acfc-b276bc439c38",
  [string]$BayId = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------
function Write-Step($msg) {
  Write-Host ""
  Write-Host ("=" * 60) -ForegroundColor Cyan
  Write-Host "  $msg" -ForegroundColor Cyan
  Write-Host ("=" * 60) -ForegroundColor Cyan
}

function Write-Check([string]$label, [bool]$pass) {
  if ($pass) {
    Write-Host "  [PASS] $label" -ForegroundColor Green
  } else {
    Write-Host "  [FAIL] $label" -ForegroundColor Red
  }
}

function Test-IsAdmin {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ==================================================================
# PHASE 1: PRE-FLIGHT CHECKS
# ==================================================================
Write-Step "Phase 1: Pre-flight Checks"

# 1a. Administrator
if (-not (Test-IsAdmin)) {
  Write-Error "This script must be run as Administrator. Right-click PowerShell and select 'Run as Administrator'."
  exit 1
}
Write-Host "  Running as Administrator: OK" -ForegroundColor Green

# 1b. Windows 11 Pro
$os = Get-CimInstance Win32_OperatingSystem
if ($os.Caption -notmatch "Pro") {
  Write-Error ("Windows 11 Pro required. Current edition: {0}. Upgrade via Settings > System > Activation > Change product key before running this script." -f $os.Caption)
  exit 1
}
Write-Host "  Windows edition: $($os.Caption) -- OK" -ForegroundColor Green

# 1c. Network connectivity
Write-Host "  Testing network connectivity to Dataverse..."
$netTest = Test-NetConnection -ComputerName "builds-apps-dev.crm.dynamics.com" -Port 443 -WarningAction SilentlyContinue
if (-not $netTest.TcpTestSucceeded) {
  Write-Error "Cannot reach builds-apps-dev.crm.dynamics.com:443. Check network connection."
  exit 1
}
Write-Host "  Dataverse connectivity: OK" -ForegroundColor Green

# 1d. Computer name
$expectedName = "BAY${BayNumber}KIOSK"
if ($env:COMPUTERNAME -ne $expectedName) {
  Write-Host "  Renaming computer from '$($env:COMPUTERNAME)' to '$expectedName'..."
  Rename-Computer -NewName $expectedName -Force
  Write-Host "  Computer renamed. A reboot is required for this to take effect." -ForegroundColor Yellow
} else {
  Write-Host "  Computer name: $expectedName -- OK" -ForegroundColor Green
}

# ==================================================================
# PHASE 2: KIOSK USER SETUP
# ==================================================================
if (-not $SkipKioskSetup) {
  Write-Step "Phase 2: BayKiosk User Setup"

  $plainPw = $null
  $existingUser = Get-LocalUser -Name $BayKioskUser -ErrorAction SilentlyContinue
  if ($existingUser) {
    Write-Host "  BayKiosk user already exists. Skipping creation." -ForegroundColor Green
  } else {
    Write-Host "  Creating local user: $BayKioskUser"
    $secPw = Read-Host "  Enter password for $BayKioskUser user" -AsSecureString
    New-LocalUser -Name $BayKioskUser -Password $secPw `
      -PasswordNeverExpires -UserMayNotChangePassword `
      -Description "Bay kiosk auto-login account for BayAgent" | Out-Null
    Add-LocalGroupMember -Group "Users" -Member $BayKioskUser -ErrorAction SilentlyContinue
    Write-Host "  User '$BayKioskUser' created." -ForegroundColor Green

    # Store password for auto-login setup below
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secPw)
    try { $plainPw = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
  }

  # Auto-login configuration
  Write-Host "  Configuring auto-login for $BayKioskUser..."
  $winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

  # If user already existed and we don't have the password, prompt for it
  if (-not $plainPw) {
    $secPw = Read-Host "  Enter password for $BayKioskUser (for auto-login)" -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secPw)
    try { $plainPw = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
  }

  Set-ItemProperty -Path $winlogonPath -Name "AutoAdminLogon" -Value "1"
  Set-ItemProperty -Path $winlogonPath -Name "DefaultUserName" -Value $BayKioskUser
  Set-ItemProperty -Path $winlogonPath -Name "DefaultPassword" -Value $plainPw
  Set-ItemProperty -Path $winlogonPath -Name "DefaultDomainName" -Value $env:COMPUTERNAME

  # Clear password from memory
  $plainPw = $null

  Write-Host "  Auto-login configured for $BayKioskUser." -ForegroundColor Green
} else {
  Write-Host "  Skipping kiosk user setup (-SkipKioskSetup)." -ForegroundColor Yellow
}

# ==================================================================
# PHASE 3: CALL DAY0
# ==================================================================
if (-not $SkipDay0) {
  Write-Step "Phase 3: Running ABG-Day0-Setup.ps1"

  # Day0 is in the tools\ folder at the repo root (sibling to src\)
  # When running on a new PC, download it first
  $day0Dir = Join-Path $AllBirdiesRoot "BayAgent\staging"
  if (-not (Test-Path $day0Dir)) { New-Item -ItemType Directory -Path $day0Dir -Force | Out-Null }
  $day0Path = Join-Path $day0Dir "ABG-Day0-Setup.ps1"

  # Download Day0 from GitHub (it lives at tools/ in the repo root, not under src/BayAgent/)
  $day0Url = "https://raw.githubusercontent.com/kedaheaven/abg-fleet-updates/main/tools/ABG-Day0-Setup.ps1"
  Write-Host "  Downloading Day0 from: $day0Url"
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  Invoke-WebRequest -Uri $day0Url -OutFile $day0Path -UseBasicParsing

  if (-not (Test-Path $day0Path)) {
    Write-Error "Failed to download ABG-Day0-Setup.ps1"
    exit 1
  }

  # Build Day0 arguments
  $day0Args = @{
    FleetRawBaseUrl       = $FleetRawBaseUrl
    AllBirdiesRoot        = $AllBirdiesRoot
    BayKioskUser          = $BayKioskUser
    CreateWatchdogTask    = $true
    CreateAgentTask       = $true
    WriteAgentConfigTemplate = $true
  }

  # Prompt for BayKiosk password for the scheduled task (Day0 needs it)
  $taskPw = Read-Host "  Enter $BayKioskUser password (for scheduled task registration)" -AsSecureString
  $bstrTask = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($taskPw)
  try { $day0Args["BayKioskPassword"] = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstrTask) }
  finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstrTask) }

  # Dataverse registration
  if ($RegisterConfigItems) {
    if ([string]::IsNullOrWhiteSpace($BayId)) {
      Write-Error "-RegisterConfigItems requires -BayId (the Dataverse build_bay GUID for this bay)."
      exit 1
    }
    $day0Args["RegisterConfigItems"] = $true
    $day0Args["EnvironmentUrl"] = $EnvironmentUrl
    $day0Args["TenantId"] = $TenantId
    $day0Args["ClientId"] = $ClientId
    $day0Args["ClientSecretDpapiPath"] = (Join-Path $AllBirdiesRoot "BayAgent\secrets\clientsecret.dpapi")
    $day0Args["BayId"] = $BayId
  }

  Write-Host "  Calling Day0 with FleetRawBaseUrl: $FleetRawBaseUrl"
  & $day0Path @day0Args

  Write-Host "  Day0 completed." -ForegroundColor Green
} else {
  Write-Host "  Skipping Day0 (-SkipDay0)." -ForegroundColor Yellow
}

# ==================================================================
# PHASE 4: EDGE POLICIES (SessionDisplay launched by shell wrapper)
# ==================================================================
if (-not $SkipKioskSetup) {
  Write-Step "Phase 4: Edge Policies for SessionDisplay"

  # Ensure Edge profile directory exists for SessionDisplay
  $edgeProfileDir = Join-Path $AllBirdiesRoot "SessionDisplay\edge-profile"
  if (-not (Test-Path $edgeProfileDir)) { New-Item -ItemType Directory -Path $edgeProfileDir -Force | Out-Null }

  # Remove legacy Startup shortcut if present (BA-20: shell wrapper now handles launch)
  $legacyShortcut = "C:\Users\$BayKioskUser\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\SessionDisplay.lnk"
  if (Test-Path $legacyShortcut) {
    Remove-Item $legacyShortcut -Force
    Write-Host "  Removed legacy Edge Startup shortcut (shell wrapper handles launch now)." -ForegroundColor Yellow
  }

  # Disable Edge first-run experience via registry
  $edgePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
  if (-not (Test-Path $edgePolicyPath)) { New-Item -Path $edgePolicyPath -Force | Out-Null }
  Set-ItemProperty -Path $edgePolicyPath -Name "HideFirstRunExperience" -Value 1 -Type DWord
  Set-ItemProperty -Path $edgePolicyPath -Name "AutoImportAtFirstRun" -Value 4 -Type DWord  # 4 = don't import
  Write-Host "  Edge first-run experience disabled." -ForegroundColor Green

  # Verify Edge is installed
  $edgePath = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
  if (-not (Test-Path $edgePath)) { $edgePath = "C:\Program Files\Microsoft\Edge\Application\msedge.exe" }
  if (Test-Path $edgePath) {
    Write-Host "  Edge found at: $edgePath" -ForegroundColor Green
  } else {
    Write-Host "  WARNING: Microsoft Edge not found. Install Edge before first boot." -ForegroundColor Yellow
  }
} else {
  Write-Host "  Skipping Edge kiosk setup (-SkipKioskSetup)." -ForegroundColor Yellow
}

# ==================================================================
# PHASE 5: WINDOWS LOCKDOWN (BA-20 -- shell replacement approach)
# ==================================================================
if (-not $SkipLockdown) {
  Write-Step "Phase 5: Windows Lockdown"

  # ------------------------------------------------------------------
  # 5A: SHELL REPLACEMENT
  # ------------------------------------------------------------------
  # Replace Explorer with ABG.LauncherShell.ps1 for BayKiosk user.
  # Admin accounts keep Explorer via HKCU override.
  #
  # How it works:
  #   - HKLM Shell = our wrapper (machine-wide default)
  #   - HKCU Shell = explorer.exe (per-user override for admin accounts)
  #   - BayKiosk has no HKCU Shell set, so HKLM applies -> our wrapper
  #   - Scheduled tasks (BayAgent, HostWatchdog) are unaffected (Task Scheduler service)
  #   - DPAPI is session-based, unaffected by shell choice
  # ------------------------------------------------------------------
  Write-Host "  Configuring custom shell replacement..."

  $shellWrapperPath = Join-Path $AllBirdiesRoot "BayAgent\bootstrap\ABG.LauncherShell.ps1"
  $psExe = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
  $shellCommand = "$psExe -NoProfile -WindowStyle Hidden -File `"$shellWrapperPath`""

  # Set machine-wide default shell to our wrapper
  $winlogonHKLM = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
  Set-ItemProperty -Path $winlogonHKLM -Name "Shell" -Value $shellCommand
  Write-Host "  HKLM Shell set to LauncherShell.ps1" -ForegroundColor Green

  # Preserve Explorer shell for the current admin user (HKCU takes precedence)
  $winlogonHKCU = "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
  if (-not (Test-Path $winlogonHKCU)) { New-Item -Path $winlogonHKCU -Force | Out-Null }
  Set-ItemProperty -Path $winlogonHKCU -Name "Shell" -Value "explorer.exe"
  Write-Host "  HKCU Shell for current admin set to explorer.exe" -ForegroundColor Green

  # Verify the wrapper script exists (it ships with the fleet package)
  if (Test-Path $shellWrapperPath) {
    Write-Host "  Shell wrapper found at: $shellWrapperPath" -ForegroundColor Green
  } else {
    Write-Host "  WARNING: Shell wrapper not found at: $shellWrapperPath" -ForegroundColor Yellow
    Write-Host "  The wrapper will be deployed by the first fleet update (Update-BayAgent.ps1)." -ForegroundColor Yellow
    Write-Host "  Until then, BayKiosk login will show a PowerShell error." -ForegroundColor Yellow
  }

  Write-Host ""
  Write-Host "  NOTE: Additional admin accounts that log in via RDP must have" -ForegroundColor Yellow
  Write-Host "  HKCU Shell set to explorer.exe. Run this on each admin account:" -ForegroundColor Yellow
  Write-Host "    New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name Shell -Value explorer.exe -Force" -ForegroundColor White

  # ------------------------------------------------------------------
  # 5B: KEYBOARD RESTRICTIONS
  # ------------------------------------------------------------------
  # With no Explorer running, many shortcuts are already inert:
  #   Win key, Win+R, Win+E, Win+D, Ctrl+Esc -- all handled by Explorer
  #
  # Remaining risks:
  #   Win+L (lock screen) -- block via DisableLockWorkstation
  #   Ctrl+Alt+Del -> Task Manager -- block via DisableTaskMgr
  #   Alt+Tab -- KEEP ENABLED (customer switches between Launcher and game)
  #   Alt+F4 -- KEEP ENABLED (launcher restarts in 2s via shell wrapper)
  #   Ctrl+Alt+Del -> other options -- limited by disabled TM + lock
  # ------------------------------------------------------------------
  Write-Host ""
  Write-Host "  Applying keyboard restrictions..."

  # Disable lock screen via Win+L
  $systemPolicyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
  if (-not (Test-Path $systemPolicyPath)) { New-Item -Path $systemPolicyPath -Force | Out-Null }
  Set-ItemProperty -Path $systemPolicyPath -Name "DisableLockWorkstation" -Value 1 -Type DWord
  Write-Host "  Win+L (lock screen) disabled." -ForegroundColor Green

  # Disable Task Manager for all users (admin can re-enable via RDP if needed)
  Set-ItemProperty -Path $systemPolicyPath -Name "DisableTaskMgr" -Value 1 -Type DWord
  Write-Host "  Task Manager disabled (Ctrl+Alt+Del limited)." -ForegroundColor Green

  # Disable command prompt for non-admin context
  $explorerPolicyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
  if (-not (Test-Path $explorerPolicyPath)) { New-Item -Path $explorerPolicyPath -Force | Out-Null }
  Set-ItemProperty -Path $explorerPolicyPath -Name "DisallowRun" -Value 0 -Type DWord

  # Disable Settings app / Control Panel
  Set-ItemProperty -Path $explorerPolicyPath -Name "NoControlPanel" -Value 1 -Type DWord
  Write-Host "  Settings/Control Panel disabled." -ForegroundColor Green

  Write-Host ""
  Write-Host "  Keyboard status with custom shell:" -ForegroundColor Cyan
  Write-Host "    Win key / Win+R / Win+E / Win+D / Ctrl+Esc -- INERT (no Explorer)" -ForegroundColor DarkGray
  Write-Host "    Win+L -- BLOCKED (DisableLockWorkstation)" -ForegroundColor DarkGray
  Write-Host "    Ctrl+Alt+Del -- LIMITED (Task Manager disabled)" -ForegroundColor DarkGray
  Write-Host "    Alt+Tab -- ENABLED (game window switching)" -ForegroundColor DarkGray
  Write-Host "    Alt+F4 -- ENABLED (launcher auto-restarts in 2s)" -ForegroundColor DarkGray

  # ------------------------------------------------------------------
  # 5C: SECURITY HARDENING (carried over from BA-19)
  # ------------------------------------------------------------------
  Write-Host ""

  # Enable Remote Desktop
  Write-Host "  Enabling Remote Desktop..."
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
  Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
  Write-Host "  Remote Desktop enabled." -ForegroundColor Green

  # Disable USB mass storage
  Write-Host "  Disabling USB mass storage..."
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start" -Value 4
  Write-Host "  USB mass storage disabled." -ForegroundColor Green

  # Disable screen saver, sleep, and display timeout
  Write-Host "  Disabling sleep and screen timeout..."
  powercfg /change monitor-timeout-ac 0
  powercfg /change standby-timeout-ac 0
  powercfg /change hibernate-timeout-ac 0
  # Disable lock screen on resume
  $personalizePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
  if (-not (Test-Path $personalizePath)) { New-Item -Path $personalizePath -Force | Out-Null }
  Set-ItemProperty -Path $personalizePath -Name "NoLockScreen" -Value 1 -Type DWord
  Write-Host "  Sleep, hibernate, and lock screen disabled." -ForegroundColor Green

  # Configure Windows Update active hours
  Write-Host "  Configuring Windows Update active hours..."
  $wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
  if (-not (Test-Path $wuPath)) { New-Item -Path $wuPath -Force | Out-Null }
  $auPath = "$wuPath\AU"
  if (-not (Test-Path $auPath)) { New-Item -Path $auPath -Force | Out-Null }
  Set-ItemProperty -Path $auPath -Name "AUOptions" -Value 4 -Type DWord
  Set-ItemProperty -Path $auPath -Name "ScheduledInstallTime" -Value 4 -Type DWord
  Set-ItemProperty -Path $auPath -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 -Type DWord
  Set-ItemProperty -Path $wuPath -Name "SetActiveHours" -Value 1 -Type DWord
  Set-ItemProperty -Path $wuPath -Name "ActiveHoursStart" -Value 5 -Type DWord
  Set-ItemProperty -Path $wuPath -Name "ActiveHoursEnd" -Value 23 -Type DWord
  Write-Host "  Windows Update active hours: 5 AM - 11 PM (installs at 4 AM)." -ForegroundColor Green

  # Disable Cortana and Search
  Write-Host "  Disabling Cortana and Search..."
  $searchPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
  if (-not (Test-Path $searchPath)) { New-Item -Path $searchPath -Force | Out-Null }
  Set-ItemProperty -Path $searchPath -Name "AllowCortana" -Value 0 -Type DWord
  Set-ItemProperty -Path $searchPath -Name "DisableWebSearch" -Value 1 -Type DWord
  Write-Host "  Cortana and web search disabled." -ForegroundColor Green

  # Disable notification center
  Write-Host "  Disabling notification center..."
  $pushPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
  if (-not (Test-Path $pushPath)) { New-Item -Path $pushPath -Force | Out-Null }
  Set-ItemProperty -Path $pushPath -Name "DisableNotificationCenter" -Value 1 -Type DWord
  Write-Host "  Notification center disabled." -ForegroundColor Green

  # Set execution policy to AllSigned
  Write-Host "  Setting execution policy to AllSigned..."
  Set-ExecutionPolicy -ExecutionPolicy AllSigned -Scope LocalMachine -Force
  Write-Host "  Execution policy set to AllSigned." -ForegroundColor Green

  # ------------------------------------------------------------------
  # 5D: DISPLAY DETECTION
  # ------------------------------------------------------------------
  Write-Host ""
  Write-Host "  Detecting connected displays..."
  try {
    Add-Type -AssemblyName System.Windows.Forms
    $allScreens = [System.Windows.Forms.Screen]::AllScreens
    Write-Host "  Displays connected: $($allScreens.Count)" -ForegroundColor Cyan
    for ($i = 0; $i -lt $allScreens.Count; $i++) {
      $scr = $allScreens[$i]
      $b = $scr.Bounds
      $pri = if ($scr.Primary) { " [PRIMARY]" } else { "" }
      Write-Host ("    Display {0}: {1} ({2}x{3} at {4},{5}){6}" -f $i, $scr.DeviceName, $b.Width, $b.Height, $b.Left, $b.Top, $pri) -ForegroundColor White
    }
    if ($allScreens.Count -lt 3) {
      Write-Host "  WARNING: Fewer than 3 displays detected. Three-display layout requires:" -ForegroundColor Yellow
      Write-Host "    Display 1 = Touchscreen (Launcher), Display 2 = Projector, Display 3 = SessionDisplay monitor" -ForegroundColor Yellow
      Write-Host "  Display configuration can be completed after physical installation." -ForegroundColor Yellow
    }
  } catch {
    Write-Host "  Could not detect displays: $($_.Exception.Message)" -ForegroundColor Yellow
  }

  # ------------------------------------------------------------------
  # 5E: ADMIN ACCESS NOTES
  # ------------------------------------------------------------------
  Write-Host ""
  Write-Host "  Admin access:" -ForegroundColor Cyan
  Write-Host "    - RDP from dev machine as admin account (not BayKiosk)" -ForegroundColor White
  Write-Host "    - On-site: Ctrl+Alt+Del -> Switch User -> admin account" -ForegroundColor White
  Write-Host "    - Admin account retains full Explorer shell" -ForegroundColor White

} else {
  Write-Host "  Skipping Windows lockdown (-SkipLockdown)." -ForegroundColor Yellow
}

# ==================================================================
# PHASE 6: DPAPI SECRET REMINDER
# ==================================================================
Write-Step "Phase 6: DPAPI Secret Setup"

$dpapiPath = Join-Path $AllBirdiesRoot "BayAgent\secrets\clientsecret.dpapi"
if (Test-Path $dpapiPath) {
  Write-Host "  DPAPI secret file exists at: $dpapiPath" -ForegroundColor Green
} else {
  Write-Host "  DPAPI secret file NOT found at: $dpapiPath" -ForegroundColor Yellow
  Write-Host ""
  Write-Host "  You must run ABG.SetClientSecretDpapi.ps1 to create the DPAPI secret." -ForegroundColor Yellow
  Write-Host "  Run this command as Administrator:" -ForegroundColor Yellow
  Write-Host ""
  Write-Host "    powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$AllBirdiesRoot\BayAgent\bootstrap\ABG.SetClientSecretDpapi.ps1`" ``" -ForegroundColor White
  Write-Host "      -OutPath `"$dpapiPath`" ``" -ForegroundColor White
  Write-Host "      -AgentAccount `".\$BayKioskUser`"" -ForegroundColor White
  Write-Host ""
  Write-Host "  You will be prompted for the Azure app client secret (Kevin has this)." -ForegroundColor Yellow
}

# ==================================================================
# PHASE 7: VERIFICATION
# ==================================================================
Write-Step "Phase 7: Verification Checklist"

$checks = @()

# Windows 11 Pro
$osCheck = Get-CimInstance Win32_OperatingSystem
$checks += [PSCustomObject]@{
  Check  = "Windows 11 Pro"
  Result = if ($osCheck.Caption -match "Pro") { "PASS" } else { "FAIL" }
}

# Computer name
$checks += [PSCustomObject]@{
  Check  = "Computer name = $expectedName"
  Result = if ($env:COMPUTERNAME -eq $expectedName) { "PASS" } else { "PENDING REBOOT (current: $($env:COMPUTERNAME))" }
}

# Folder structure
$requiredFolders = @(
  (Join-Path $AllBirdiesRoot "BayAgent"),
  (Join-Path $AllBirdiesRoot "BayAgent\bootstrap"),
  (Join-Path $AllBirdiesRoot "BayAgent\tools"),
  (Join-Path $AllBirdiesRoot "BayAgent\current"),
  (Join-Path $AllBirdiesRoot "BayAgent\secrets"),
  (Join-Path $AllBirdiesRoot "BayAgent\logs"),
  (Join-Path $AllBirdiesRoot "BayAgent\control"),
  (Join-Path $AllBirdiesRoot "SessionDisplay"),
  (Join-Path $AllBirdiesRoot "SessionDisplay\current"),
  (Join-Path $AllBirdiesRoot "SessionDisplay\data")
)

foreach ($folder in $requiredFolders) {
  $shortName = $folder.Replace($AllBirdiesRoot, "")
  $checks += [PSCustomObject]@{
    Check  = "Folder: $shortName"
    Result = if (Test-Path $folder) { "PASS" } else { "FAIL" }
  }
}

# Bootstrap scripts
$bootstrapFiles = @(
  (Join-Path $AllBirdiesRoot "BayAgent\bootstrap\ABG.AgentHost.ps1"),
  (Join-Path $AllBirdiesRoot "BayAgent\bootstrap\ABG.HostWatchdog.ps1")
)
foreach ($f in $bootstrapFiles) {
  $fname = Split-Path $f -Leaf
  $checks += [PSCustomObject]@{
    Check  = "Bootstrap: $fname"
    Result = if (Test-Path $f) { "PASS" } else { "FAIL" }
  }
}

# Tools scripts
$toolFiles = @(
  (Join-Path $AllBirdiesRoot "BayAgent\tools\Update-BayAgent.ps1"),
  (Join-Path $AllBirdiesRoot "BayAgent\tools\Update-SessionDisplay.ps1"),
  (Join-Path $AllBirdiesRoot "BayAgent\tools\Update-PromosPack.ps1")
)
foreach ($f in $toolFiles) {
  $fname = Split-Path $f -Leaf
  $checks += [PSCustomObject]@{
    Check  = "Tool: $fname"
    Result = if (Test-Path $f) { "PASS" } else { "FAIL" }
  }
}

# agent-config.json
$checks += [PSCustomObject]@{
  Check  = "agent-config.json present"
  Result = if (Test-Path (Join-Path $AllBirdiesRoot "BayAgent\agent-config.json")) { "PASS" } else { "FAIL" }
}

# SessionDisplay data files
foreach ($df in @("session.json", "promos.json")) {
  $checks += [PSCustomObject]@{
    Check  = "Data file: $df"
    Result = if (Test-Path (Join-Path $AllBirdiesRoot "SessionDisplay\data\$df")) { "PASS" } else { "FAIL" }
  }
}

# DPAPI secret
$checks += [PSCustomObject]@{
  Check  = "DPAPI secret exists"
  Result = if (Test-Path $dpapiPath) { "PASS" } else { "PENDING (run SetClientSecretDpapi)" }
}

# Code signing cert
$sigCert = @(Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object {
  $_.EnhancedKeyUsageList.FriendlyName -contains "Code Signing" -and
  $_.HasPrivateKey -and
  $_.Subject -like "*ABG*"
})
$checks += [PSCustomObject]@{
  Check  = "Code signing certificate"
  Result = if ($sigCert.Count -gt 0) { "PASS (Thumbprint=$($sigCert[0].Thumbprint))" } else { "FAIL" }
}

# Scheduled tasks
foreach ($taskName in @("ABG Bay Agent", "ABG Host Watchdog")) {
  $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
  $checks += [PSCustomObject]@{
    Check  = "Scheduled task: $taskName"
    Result = if ($task) { "PASS ($($task.State))" } else { "FAIL" }
  }
}

# BayKiosk user
$checks += [PSCustomObject]@{
  Check  = "BayKiosk user exists"
  Result = if (Get-LocalUser -Name $BayKioskUser -ErrorAction SilentlyContinue) { "PASS" } else { "FAIL" }
}

# Auto-login
$autoLogin = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogon -ErrorAction SilentlyContinue).AutoAdminLogon
$checks += [PSCustomObject]@{
  Check  = "Auto-login enabled"
  Result = if ($autoLogin -eq "1") { "PASS" } else { "FAIL" }
}

# RDP enabled
$rdp = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections
$checks += [PSCustomObject]@{
  Check  = "Remote Desktop enabled"
  Result = if ($rdp -eq 0) { "PASS" } else { "FAIL" }
}

# USB storage disabled
$usb = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name Start -ErrorAction SilentlyContinue).Start
$checks += [PSCustomObject]@{
  Check  = "USB storage disabled"
  Result = if ($usb -eq 4) { "PASS" } else { "FAIL" }
}

# Network connectivity
$checks += [PSCustomObject]@{
  Check  = "Dataverse connectivity"
  Result = if ($netTest.TcpTestSucceeded) { "PASS" } else { "FAIL" }
}

# Shell wrapper script
$shellWrapperCheck = Join-Path $AllBirdiesRoot "BayAgent\bootstrap\ABG.LauncherShell.ps1"
$checks += [PSCustomObject]@{
  Check  = "Shell wrapper script"
  Result = if (Test-Path $shellWrapperCheck) { "PASS" } else { "PENDING (deployed by fleet update)" }
}

# Custom shell configured (HKLM)
$hklmShell = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name Shell -ErrorAction SilentlyContinue).Shell
$checks += [PSCustomObject]@{
  Check  = "Custom shell (HKLM)"
  Result = if ($hklmShell -like "*LauncherShell*") { "PASS" } else { "FAIL (Shell=$hklmShell)" }
}

# Admin shell override (HKCU)
$hkcuShell = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name Shell -ErrorAction SilentlyContinue).Shell
$checks += [PSCustomObject]@{
  Check  = "Admin shell override (HKCU)"
  Result = if ($hkcuShell -eq "explorer.exe") { "PASS" } else { "FAIL" }
}

# Keyboard: Win+L disabled
$lockWs = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name DisableLockWorkstation -ErrorAction SilentlyContinue).DisableLockWorkstation
$checks += [PSCustomObject]@{
  Check  = "Win+L (lock) disabled"
  Result = if ($lockWs -eq 1) { "PASS" } else { "FAIL" }
}

# Keyboard: Task Manager disabled
$disTm = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name DisableTaskMgr -ErrorAction SilentlyContinue).DisableTaskMgr
$checks += [PSCustomObject]@{
  Check  = "Task Manager disabled"
  Result = if ($disTm -eq 1) { "PASS" } else { "FAIL" }
}

# Display count
$displayCount = 0
try {
  Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
  $displayCount = ([System.Windows.Forms.Screen]::AllScreens).Count
} catch {}
$checks += [PSCustomObject]@{
  Check  = "Display count (3 required)"
  Result = if ($displayCount -ge 3) { "PASS ($displayCount displays)" } else { "SKIP ($displayCount displays -- connect all 3 for final verification)" }
}

# Execution policy
$execPolicy = Get-ExecutionPolicy -Scope LocalMachine
$checks += [PSCustomObject]@{
  Check  = "Execution policy (AllSigned)"
  Result = if ($execPolicy -eq "AllSigned") { "PASS" } else { "WARN ($execPolicy)" }
}

# Print summary
Write-Host ""
$checks | Format-Table -AutoSize -Property Check, Result

$failCount = ($checks | Where-Object { $_.Result -match "FAIL" }).Count
$pendingCount = ($checks | Where-Object { $_.Result -match "PENDING" }).Count
$passCount = ($checks | Where-Object { $_.Result -match "PASS" }).Count

Write-Host ""
if ($failCount -eq 0 -and $pendingCount -eq 0) {
  Write-Host "ALL $passCount CHECKS PASSED" -ForegroundColor Green
} elseif ($failCount -eq 0) {
  Write-Host "$passCount PASSED, $pendingCount PENDING (non-blocking)" -ForegroundColor Yellow
} else {
  Write-Host "$passCount PASSED, $failCount FAILED, $pendingCount PENDING" -ForegroundColor Red
}

# ==================================================================
# PHASE 8: NEXT STEPS
# ==================================================================
Write-Step "Next Steps"

$nextSteps = @()
if (-not (Test-Path $dpapiPath)) {
  $nextSteps += "1. Run ABG.SetClientSecretDpapi.ps1 to create the DPAPI secret (see Phase 6 output above)"
}
if ($env:COMPUTERNAME -ne $expectedName) {
  $nextSteps += "2. Reboot to apply the computer name change to '$expectedName'"
}
$nextSteps += "3. Edit agent-config.json with bay-specific values (environmentUrl, bayId, tenantId, clientId)"
$nextSteps += "4. Configure display arrangement:"
$nextSteps += "     Display 1 = Touchscreen (primary, Launcher)"
$nextSteps += "     Display 2 = Projector (gameplay)"
$nextSteps += "     Display 3 = Monitor (SessionDisplay)"
$nextSteps += "   Update displayRouting.roles in agent-config.json if display order differs"
$nextSteps += "5. Reboot and verify kiosk mode:"
$nextSteps += "     - BayKiosk auto-logs in (no desktop, no taskbar, no Start menu)"
$nextSteps += "     - Uneekor Launcher appears on touchscreen (Display 1)"
$nextSteps += "     - SessionDisplay appears on monitor (Display 3)"
$nextSteps += "     - Windows key does nothing"
$nextSteps += "     - Closing Launcher -> restarts in 2-3 seconds"
$nextSteps += "6. Check the MDA: Ops > Bays -- the new bay should appear Online within 2 minutes"
$nextSteps += "7. Send a HealthCheck from the MDA to verify end-to-end"
$nextSteps += "8. Install Uneekor software and update agent-config.json launcher path"

foreach ($step in $nextSteps) {
  Write-Host "  $step" -ForegroundColor White
}

# ==================================================================
# REBOOT
# ==================================================================
if (-not $SkipReboot) {
  Write-Host ""
  Write-Host "  The PC needs to reboot for all changes to take effect." -ForegroundColor Yellow
  $rebootChoice = Read-Host "  Reboot now? (y/N)"
  if ($rebootChoice -eq "y") {
    Write-Host "  Rebooting in 10 seconds..." -ForegroundColor Yellow
    shutdown /r /t 10 /c "ABG Bay PC provisioning complete -- rebooting"
  } else {
    Write-Host "  Skipping reboot. Remember to reboot manually." -ForegroundColor Yellow
  }
}

Write-Step "Setup-BayPC.ps1 Complete"
