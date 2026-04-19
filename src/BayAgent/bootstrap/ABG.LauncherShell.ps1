<#
ABG.LauncherShell.ps1 (BA-20)
Custom Windows shell for BayKiosk user. Replaces explorer.exe.

Launched by WinLogon as the shell process for BayKiosk. Manages:
  1. SessionDisplay (Edge kiosk on the "session" display)
  2. Uneekor Launcher (on the "control" display / touchscreen)

If either process exits, this wrapper restarts it after a short delay.
If THIS script exits, Windows logs the user off and auto-login re-logs in.

IMPORTANT:
  - ASCII-only comments (no em-dashes) for AllSigned compatibility
  - This script must be extremely robust -- if it crashes, user sees blank screen
  - Scheduled tasks (BayAgent, HostWatchdog) run independently of the shell
  - DPAPI context is session-based, unaffected by shell replacement
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ------------------------------------------------------------------
# Config
# ------------------------------------------------------------------
$BaseDir  = "C:\AllBirdies\BayAgent"
$LogDir   = Join-Path $BaseDir "logs"
$CfgPath  = Join-Path $BaseDir "agent-config.json"

if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Force -Path $LogDir | Out-Null }

$LogFile = Join-Path $LogDir ("LauncherShell-{0}.log" -f (Get-Date).ToString("yyyyMMdd"))

# ------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------
function Write-ShellLog([string]$msg, [ValidateSet("DEBUG","INFO","WARN","ERROR")] [string]$level="INFO") {
    $ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $line = "$ts [$level] $msg"
    try { Add-Content -Path $LogFile -Value $line -Encoding UTF8 } catch {}
}

# ------------------------------------------------------------------
# Display helpers
# ------------------------------------------------------------------
function Get-ScreenBoundsForSelector([string]$selector, $screens) {
    if ($null -eq $screens -or $screens.Count -eq 0) { return $null }
    if ([string]::IsNullOrWhiteSpace($selector)) { return $null }

    $sel = $selector.Trim()

    # Direct DeviceName match (e.g. "\\.\DISPLAY3")
    foreach ($s in $screens) {
        if ($s.DeviceName -ieq $sel) { return $s.Bounds }
    }

    # Shorthand match (e.g. "DISPLAY3")
    if ($sel -match '^DISPLAY\d+$') {
        $full = "\\.\$sel"
        foreach ($s in $screens) {
            if ($s.DeviceName -ieq $full) { return $s.Bounds }
        }
    }

    # Numeric index
    try {
        $idx = [int]$sel
        if ($idx -ge 0 -and $idx -lt $screens.Count) {
            return $screens[$idx].Bounds
        }
    } catch {}

    return $null
}

function Get-SessionDisplayBounds($cfg, $screens) {
    # Resolve the "session" role from displayRouting config
    $selector = $null
    try {
        $dr = $cfg.displayRouting
        if ($null -ne $dr -and $dr.enabled -eq $true) {
            $roles = $dr.roles
            if ($null -ne $roles) {
                $sessionRole = $roles.session
                if ($null -ne $sessionRole) {
                    $selector = $sessionRole.selector
                }
            }
        }
    } catch {}

    if (-not [string]::IsNullOrWhiteSpace([string]$selector)) {
        $bounds = Get-ScreenBoundsForSelector $selector $screens
        if ($null -ne $bounds) { return $bounds }
    }

    # Fallback: last non-primary display (matches BayAgent behavior)
    $nonPrimary = @($screens | Where-Object { -not $_.Primary })
    if ($nonPrimary.Count -gt 0) {
        return $nonPrimary[$nonPrimary.Count - 1].Bounds
    }

    # Last resort: primary display
    return $screens[0].Bounds
}

function Get-DisplaySummary($screens) {
    $lines = @()
    for ($i = 0; $i -lt $screens.Count; $i++) {
        $s = $screens[$i]
        $b = $s.Bounds
        $pri = if ($s.Primary) { " [PRIMARY]" } else { "" }
        $lines += ("  Display {0}: {1} ({2}x{3} at {4},{5}){6}" -f $i, $s.DeviceName, $b.Width, $b.Height, $b.Left, $b.Top, $pri)
    }
    return ($lines -join "`n")
}

# ------------------------------------------------------------------
# Edge launch helper
# ------------------------------------------------------------------
function Start-EdgeKiosk([string]$edgePath, [string]$url, [string]$profileDir, $bounds) {
    $args = "--kiosk `"$url`" --edge-kiosk-type=fullscreen --kiosk-idle-timeout-minutes=0"
    $args += " --user-data-dir=`"$profileDir`" --no-first-run --no-default-browser-check --disable-features=msEdgeSidebarV2"
    $args += " --allow-file-access-from-files"

    if ($null -ne $bounds) {
        $args += " --window-position=$($bounds.Left),$($bounds.Top)"
        $args += " --window-size=$($bounds.Width),$($bounds.Height)"
    }

    Write-ShellLog "Starting Edge kiosk: $edgePath $args" "INFO"
    $proc = Start-Process -FilePath $edgePath -ArgumentList $args -PassThru
    return $proc
}

# ------------------------------------------------------------------
# Edge process detection (matches BayAgent pattern)
# ------------------------------------------------------------------
function Get-EdgePidsForProfile([string]$profileDir) {
    $ids = @()
    try {
        $edgeCim = Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" -OperationTimeoutSec 3 -ErrorAction SilentlyContinue
        foreach ($p in $edgeCim) {
            $cmd = $p.CommandLine
            if ($null -ne $cmd -and $cmd -like "*$profileDir*") { $ids += [int]$p.ProcessId }
        }
    } catch {}
    return $ids
}

function Test-EdgeRunning([string]$profileDir) {
    $pids = @(Get-EdgePidsForProfile $profileDir)
    return ($pids.Count -gt 0)
}

# ------------------------------------------------------------------
# Launcher process detection
# ------------------------------------------------------------------
function Test-LauncherRunning([string]$processName) {
    if ([string]::IsNullOrWhiteSpace([string]$processName)) { return $false }
    $base = [System.IO.Path]::GetFileNameWithoutExtension([string]$processName)
    $procs = Get-Process -Name $base -ErrorAction SilentlyContinue
    return ($null -ne $procs -and @($procs).Count -gt 0)
}

# ------------------------------------------------------------------
# Edge path resolution
# ------------------------------------------------------------------
function Get-EdgePath {
    $paths = @(
        "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        "C:\Program Files\Microsoft\Edge\Application\msedge.exe"
    )
    foreach ($p in $paths) {
        if (Test-Path $p) { return $p }
    }
    return $null
}

# ==================================================================
# MAIN
# ==================================================================

# Outer loop: if an unhandled exception escapes the inner try/catch,
# this loop restarts the whole shell logic after a brief delay.
# This prevents the shell process from exiting (which would log off the user).
while ($true) {
    try {
        Write-ShellLog "========== LauncherShell starting (PID=$PID) ==========" "INFO"

        # ---- Load config ----
        $cfg = $null
        if (Test-Path $CfgPath) {
            try {
                $raw = Get-Content $CfgPath -Raw -Encoding UTF8
                $cfg = $raw | ConvertFrom-Json
                Write-ShellLog "Config loaded from $CfgPath" "INFO"
            } catch {
                Write-ShellLog "Failed to parse config: $($_.Exception.Message)" "ERROR"
            }
        } else {
            Write-ShellLog "Config not found at $CfgPath -- using defaults" "WARN"
        }

        # ---- Resolve launcher settings ----
        $launcherPath = "C:\Uneekor\Launcher\UneekorLauncher.exe"
        $launcherProcessName = "UneekorLauncher"
        $launcherArgs = ""

        if ($null -ne $cfg -and $null -ne $cfg.launcher) {
            $lc = $cfg.launcher
            if (-not [string]::IsNullOrWhiteSpace([string]$lc.path)) { $launcherPath = $lc.path }
            if (-not [string]::IsNullOrWhiteSpace([string]$lc.processName)) { $launcherProcessName = $lc.processName }
            if (-not [string]::IsNullOrWhiteSpace([string]$lc.args)) { $launcherArgs = $lc.args }
        }

        # ---- Resolve session display settings ----
        $sdUrl = "file:///C:/AllBirdies/SessionDisplay/current/index.html"
        $sdProfileDir = "C:\AllBirdies\SessionDisplay\edge-profile"

        if ($null -ne $cfg -and $null -ne $cfg.sessionDisplay) {
            $sd = $cfg.sessionDisplay
            if (-not [string]::IsNullOrWhiteSpace([string]$sd.url)) { $sdUrl = $sd.url }
            if (-not [string]::IsNullOrWhiteSpace([string]$sd.profileDir)) { $sdProfileDir = $sd.profileDir }
        }

        if (!(Test-Path $sdProfileDir)) { New-Item -ItemType Directory -Path $sdProfileDir -Force | Out-Null }

        # ---- Detect displays ----
        try { Add-Type -AssemblyName System.Windows.Forms } catch {
            Write-ShellLog "Cannot load System.Windows.Forms: $($_.Exception.Message)" "ERROR"
        }

        $screens = @()
        try { $screens = [System.Windows.Forms.Screen]::AllScreens } catch {}

        Write-ShellLog "Displays detected: $($screens.Count)" "INFO"
        if ($screens.Count -gt 0) {
            Write-ShellLog (Get-DisplaySummary $screens) "INFO"
        }

        # ---- Resolve session display bounds ----
        $sessionBounds = $null
        if ($screens.Count -gt 0 -and $null -ne $cfg) {
            $sessionBounds = Get-SessionDisplayBounds $cfg $screens
        }

        if ($null -ne $sessionBounds) {
            Write-ShellLog ("Session display target: {0}x{1} at {2},{3}" -f $sessionBounds.Width, $sessionBounds.Height, $sessionBounds.Left, $sessionBounds.Top) "INFO"
        } else {
            Write-ShellLog "No session display bounds resolved (single display or no config)" "WARN"
        }

        # ---- Resolve Edge path ----
        $edgePath = Get-EdgePath
        if ($null -eq $edgePath) {
            Write-ShellLog "Microsoft Edge not found -- SessionDisplay will not start" "ERROR"
        }

        # ---- Initial launch: SessionDisplay (Edge kiosk) ----
        $edgeProc = $null
        if ($null -ne $edgePath) {
            if (Test-EdgeRunning $sdProfileDir) {
                Write-ShellLog "Edge kiosk already running for SessionDisplay profile" "INFO"
            } else {
                $edgeProc = Start-EdgeKiosk $edgePath $sdUrl $sdProfileDir $sessionBounds
                Write-ShellLog "Edge kiosk started (PID=$($edgeProc.Id))" "INFO"
            }
        }

        # Short delay before launching launcher (let Edge settle)
        Start-Sleep -Seconds 2

        # ---- Initial launch: Uneekor Launcher ----
        $launcherProc = $null
        if (Test-Path $launcherPath) {
            if (Test-LauncherRunning $launcherProcessName) {
                Write-ShellLog "Launcher already running: $launcherProcessName" "INFO"
            } else {
                Write-ShellLog "Starting launcher: $launcherPath" "INFO"
                if ([string]::IsNullOrWhiteSpace($launcherArgs)) {
                    $launcherProc = Start-Process -FilePath $launcherPath -PassThru
                } else {
                    $launcherProc = Start-Process -FilePath $launcherPath -ArgumentList $launcherArgs -PassThru
                }
                Write-ShellLog "Launcher started (PID=$($launcherProc.Id))" "INFO"
            }
        } else {
            Write-ShellLog "Launcher not found at: $launcherPath -- will retry in monitor loop" "WARN"
        }

        # ==============================================================
        # Monitor loop -- runs forever, restarts processes if they exit
        # ==============================================================
        $launcherRestartDelay = 2
        $edgeRestartDelay = 3
        $checkInterval = 2
        $edgeCheckCounter = 0
        $edgeCheckFrequency = 15  # Check Edge every 15 cycles (30 seconds)

        Write-ShellLog "Entering monitor loop (check every ${checkInterval}s)" "INFO"

        while ($true) {
            Start-Sleep -Seconds $checkInterval

            # ---- Check launcher ----
            $launcherRunning = Test-LauncherRunning $launcherProcessName
            if (-not $launcherRunning -and (Test-Path $launcherPath)) {
                Write-ShellLog "Launcher exited -- restarting in ${launcherRestartDelay}s" "WARN"
                Start-Sleep -Seconds $launcherRestartDelay
                try {
                    if ([string]::IsNullOrWhiteSpace($launcherArgs)) {
                        $launcherProc = Start-Process -FilePath $launcherPath -PassThru
                    } else {
                        $launcherProc = Start-Process -FilePath $launcherPath -ArgumentList $launcherArgs -PassThru
                    }
                    Write-ShellLog "Launcher restarted (PID=$($launcherProc.Id))" "INFO"
                } catch {
                    Write-ShellLog "Failed to restart launcher: $($_.Exception.Message)" "ERROR"
                }
            }

            # ---- Check Edge (less frequently -- Edge is stable) ----
            $edgeCheckCounter++
            if ($edgeCheckCounter -ge $edgeCheckFrequency) {
                $edgeCheckCounter = 0
                if ($null -ne $edgePath) {
                    $edgeRunning = Test-EdgeRunning $sdProfileDir
                    if (-not $edgeRunning) {
                        Write-ShellLog "Edge kiosk exited -- restarting in ${edgeRestartDelay}s" "WARN"
                        Start-Sleep -Seconds $edgeRestartDelay

                        # Re-detect displays (may have changed)
                        try {
                            $screens = [System.Windows.Forms.Screen]::AllScreens
                            if ($null -ne $cfg) {
                                $sessionBounds = Get-SessionDisplayBounds $cfg $screens
                            }
                        } catch {}

                        try {
                            $edgeProc = Start-EdgeKiosk $edgePath $sdUrl $sdProfileDir $sessionBounds
                            Write-ShellLog "Edge kiosk restarted (PID=$($edgeProc.Id))" "INFO"
                        } catch {
                            Write-ShellLog "Failed to restart Edge kiosk: $($_.Exception.Message)" "ERROR"
                        }
                    }
                }
            }

            # ---- Rotate log file at midnight ----
            $expectedLog = Join-Path $LogDir ("LauncherShell-{0}.log" -f (Get-Date).ToString("yyyyMMdd"))
            if ($expectedLog -ne $LogFile) {
                $LogFile = $expectedLog
            }
        }
    }
    catch {
        # If anything escapes the inner logic, log it and retry
        try { Write-ShellLog "Shell fatal error: $($_.Exception.Message) -- restarting in 5s" "ERROR" } catch {}
        Start-Sleep -Seconds 5
        # Loop restarts the entire shell logic
    }
}
