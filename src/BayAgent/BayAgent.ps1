<#
ABG Bay Agent (Production Baseline v2 - includes periodic heartbeat)
- Step 1 foundation: Entra client-credentials auth, Dataverse polling, optimistic lock, execute, report
- Adds: automatic Bay heartbeat update every HeartbeatSeconds (default 60) even when no commands exist
- Extend by adding new command handlers in Execute-Command()

Run examples:
  # One-time auth + poll iteration then exit:
  powershell.exe -NoProfile -File "C:\AllBirdies\BayAgent\BayAgent.ps1" -Once

  # Run continuously:
  powershell.exe -NoProfile -File "C:\AllBirdies\BayAgent\BayAgent.ps1"

Optional switches:
  -TokenOnly   Acquire token then exit (auth test)
  -Once        Run one poll iteration then exit
#>

param(
    [switch]$Once,
    [switch]$TokenOnly
)

Set-StrictMode -Version Latest
try { Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue } catch {}
$ErrorActionPreference = "Stop"

# Helps on some Windows PowerShell stacks; harmless on Win11
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

# ---------------- Paths ----------------
$BaseDir = "C:\AllBirdies\BayAgent"
$CfgPath = Join-Path $BaseDir "agent-config.json"
$LogDir  = Join-Path $BaseDir "logs"

if (!(Test-Path $BaseDir)) { New-Item -ItemType Directory -Path $BaseDir | Out-Null }
if (!(Test-Path $LogDir))  { New-Item -ItemType Directory -Path $LogDir  | Out-Null }
if (!(Test-Path $CfgPath)) { throw "Config file not found: $CfgPath" }

# ---------------- Logging ----------------
# Levels: DEBUG, INFO, WARN, ERROR
$Global:LogLevel = "INFO"  # change to DEBUG when troubleshooting
$LogFile = Join-Path $LogDir ("BayAgent-{0}.log" -f (Get-Date).ToString("yyyyMMdd"))

function Get-LogLevelRank([string]$lvl) {
    switch ($lvl.ToUpperInvariant()) {
        "DEBUG" { 0 }
        "INFO"  { 1 }
        "WARN"  { 2 }
        "ERROR" { 3 }
        default { 1 }
    }
}

function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet("DEBUG","INFO","WARN","ERROR")][string]$Level = "INFO"
    )
    if ((Get-LogLevelRank $Level) -lt (Get-LogLevelRank $Global:LogLevel)) { return }

    $ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $line = "$ts [$Level] $Message"
    try { Write-Host $line } catch {}
    try { Add-Content -Path $LogFile -Value $line } catch {}
}


# ---------------- Fatal error trap ----------------
# If something blows up outside the main loop (e.g., config parse, auth init), we still want a clear log line.
# NOTE: This trap only fires for UNHANDLED terminating errors.
trap {
    $err = $_
    $msg = $null
    try { $msg = $err.Exception.Message } catch { $msg = [string]$err }
    try { Write-Log ("FATAL (pid={0}): {1}" -f $PID, $msg) "ERROR" } catch {}
    try {
        if ($err.ScriptStackTrace) { Write-Log ("STACK: {0}" -f $err.ScriptStackTrace) "ERROR" }
    } catch {}
    exit 1
}

# ---------------- Config ----------------
$cfg = Get-Content $CfgPath -Raw | ConvertFrom-Json

function Require-Config([string]$name) {
    if (-not ($cfg.PSObject.Properties.Name -contains $name) -or [string]::IsNullOrWhiteSpace($cfg.$name)) {
        throw "Missing or empty config field '$name' in $CfgPath"
    }
}

# environmentUrl is preferred; dataverseUrl accepted as an alias
function Get-ConfigString([string[]]$names) {
    foreach ($n in $names) {
        try {
            if ($cfg.PSObject.Properties.Name -contains $n) {
                $v = $cfg.$n
                if ($null -ne $v) {
                    $s = ($v.ToString()).Trim()
                    if (-not [string]::IsNullOrWhiteSpace($s)) { return $s }
                }
            }
        } catch {}
    }
    return $null
}

$OrgUrlRaw = Get-ConfigString @("environmentUrl","dataverseUrl")
if ([string]::IsNullOrWhiteSpace($OrgUrlRaw)) {
    throw "Missing or empty config field 'environmentUrl' (or 'dataverseUrl') in $CfgPath"
}
$OrgUrl = $OrgUrlRaw.TrimEnd("/")

Require-Config "tenantId"
Require-Config "clientId"
Require-Config "bayId"
Require-Config "pollSeconds"

$TenantId = $cfg.tenantId.ToString()
$ClientId = $cfg.clientId.ToString()
# Auth can be provided by:
# - clientSecretDpapiPath (preferred)
# - clientSecret (legacy fallback for transition)
$Secret     = $null
$SecretPath = $null

$hasDpapiPath = ($cfg.PSObject.Properties.Name -contains "clientSecretDpapiPath") -and
                (-not [string]::IsNullOrWhiteSpace($cfg.clientSecretDpapiPath))

$hasPlaintext = ($cfg.PSObject.Properties.Name -contains "clientSecret") -and
                (-not [string]::IsNullOrWhiteSpace($cfg.clientSecret))

if ($hasDpapiPath) {
    $SecretPath = $cfg.clientSecretDpapiPath.ToString().Trim()

    # Fail fast if configured but missing (don’t silently fall back)
    if (!(Test-Path $SecretPath)) {
        throw "clientSecretDpapiPath is set but file not found: $SecretPath"
    }

    Write-Log ("Auth mode: DPAPI (path={0})" -f $SecretPath) "INFO"
}
elseif ($hasPlaintext) {
    $Secret = $cfg.clientSecret.ToString().Trim()
    Write-Log "Auth mode: PLAINTEXT (legacy)" "WARN"
}
else {
    throw "Missing auth config: provide clientSecretDpapiPath (preferred) or clientSecret (legacy) in $CfgPath"
}

function Get-ClientSecret {
    if ($Secret) { 
        return $Secret.Trim()
    }

    if ([string]::IsNullOrWhiteSpace($SecretPath)) { 
        throw "SecretPath not configured" 
    }

    if (!(Test-Path $SecretPath)) { 
        throw "Secret file not found: $SecretPath" 
    }

    $enc = [IO.File]::ReadAllBytes($SecretPath)

    $bytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $enc,
        $null,
        [System.Security.Cryptography.DataProtectionScope]::LocalMachine
    )

    $s = ([Text.Encoding]::UTF8.GetString($bytes)).Trim()
    Write-Log ("Loaded DPAPI secret from {0} (length={1})" -f $SecretPath, $s.Length) "DEBUG"
    return $s
}

$BayId    = ($cfg.bayId.ToString()).Trim("{}")
$PollSec  = [int]$cfg.pollSeconds

# Optional config
if ($cfg.PSObject.Properties.Name -contains "logLevel" -and -not [string]::IsNullOrWhiteSpace($cfg.logLevel)) {
    $Global:LogLevel = $cfg.logLevel.ToString().ToUpperInvariant()
}

# Heartbeat cadence (seconds). Defaults to 60.
$HeartbeatSec = 60
if ($cfg.PSObject.Properties.Name -contains "heartbeatSeconds" -and $cfg.heartbeatSeconds) {
    try { $HeartbeatSec = [int]$cfg.heartbeatSeconds } catch {}
    if ($script:HeartbeatSec -lt 15) { $script:HeartbeatSec = 15 } # floor to avoid accidental thrash
}

# Release version (prefer manifest.json next to this script)
$AgentVersion = "dev"

try {
    $manifestPath = Join-Path $PSScriptRoot "manifest.json"
    if (Test-Path $manifestPath) {
        $m = Get-Content $manifestPath -Raw | ConvertFrom-Json
        if ($m -and $m.version) { $AgentVersion = [string]$m.version }
    }
} catch {
    # If manifest read fails, keep "dev" and continue
}

Write-Log "BayAgent starting. pid=$PID. OrgUrl=$OrgUrl BayId=$BayId PollSec=$PollSec HeartbeatSec=$HeartbeatSec LogLevel=$Global:LogLevel Version=$AgentVersion TokenOnly=$TokenOnly Once=$Once" "INFO"

# ---------------- Dataverse schema (your verified names) ----------------
$BayCommandEntitySet = "build_baycommands"
$BayEntitySet        = "build_baies"


# ---------------- Step 8.2: Dynamic config entities (BayProfile + ConfigItem overlay) ----------------
$BayProfileEntitySet  = "build_bayprofiles"
$ConfigItemEntitySet  = "build_configitems"
$LocationEntitySet    = "build_locations"

# Bay lookup columns (Web API exposes these as _{lookup}_value)
$Lookup_Location      = "build_location"
$Lookup_LocationValue = "_{0}_value" -f $Lookup_Location

$Lookup_BayProfile      = "build_bayprofile"
$Lookup_BayProfileValue = "_{0}_value" -f $Lookup_BayProfile

# Bay operational status columns (Step 8)
$Col_AgentStatus       = "build_agentstatus"
$Col_AgentStatusUntil  = "build_agentstatusuntil"
$Col_AgentStatusReason = "build_agentstatusreason"
$Col_AgentCapsJson     = "build_agentcapabilitiesjson"

# Location columns
$Col_TimeZoneId = "build_timezoneid"

# BayProfile columns (logical names)
$Col_BP_LauncherPath       = "build_launcherpath"
$Col_BP_LauncherArgs       = "build_launcherargs"
$Col_BP_LauncherProcName   = "build_launcherprocessname"
$Col_BP_SessionMode        = "build_sessiondisplaymode"
$Col_BP_SessionJsonPath    = "build_sessionjsonpath"
$Col_BP_ProfileJson        = "build_profilejson"

# ConfigItem columns (logical names)
$Col_CI_Scope   = "build_scope"
$Col_CI_Key     = "build_key"
$Col_CI_Value   = "build_value"
$Col_CI_Enabled = "build_enabled"

# IMPORTANT: Update these to match your ConfigItem.Scope choice values in Dataverse if different
$SCOPE_GLOBAL   = 100000000
$SCOPE_LOCATION = 100000001
$SCOPE_BAY      = 100000002

# Dynamic config refresh cadence (seconds)
$ConfigRefreshSec = 300
# BayCommand columns (logical names)
$Col_CommandId    = "build_baycommandid"
$Col_Status       = "build_status"
$Col_CommandType  = "build_commandtype"
$Col_NotBefore    = "build_notbefore"
$Col_AttemptCount = "build_attemptcount"
$Col_StartedOn    = "build_startedon"
$Col_CompletedOn  = "build_completedon"
$Col_Payload      = "build_payload"
$Col_Result       = "build_resultjson"
$Col_Error        = "build_errordetails"

# Lookup logical name for Bay lookup in BayCommand (Web API filter uses _{lookup}_value)
$Lookup_Bay      = "build_bay"
$Lookup_BayValue = "_{0}_value" -f $Lookup_Bay

# Bay columns (logical names)
$Col_Heartbeat = "build_lastheartbeat"
$Col_Machine   = "build_agentmachinename"
$Col_Version   = "build_agentversion"

# Choice values
$STATUS_PENDING    = 100000000
$STATUS_INPROGRESS = 100000001
$STATUS_SUCCEEDED  = 100000002
$STATUS_FAILED     = 100000003


# Bay Agent status values (build_agentstatus)
# NOTE: These must match your Dataverse choice values for the Bay table column build_agentstatus.
$AGENTSTATUS_ONLINE      = 100000000
$AGENTSTATUS_DEGRADED    = 100000001
$AGENTSTATUS_OFFLINE     = 100000002
$AGENTSTATUS_MAINTENANCE = 100000003

# Command type values (Step 2 primitives included)
$CMD_HEALTHCHECK   = 100000000
$CMD_SHOWMESSAGE  = 100000001
$CMD_STARTPROCESS = 100000002
$CMD_STOPPROCESS  = 100000003
$CMD_QUERYPROCESS = 100000004
$CMD_UPDATESESSIONDISPLAY = 100000005
$CMD_STARTSESSION = 100000010
$CMD_ENDSESSION   = 100000011
$CMD_RESET        = 100000012



# Step 5 command types (add matching Choice values in Dataverse build_commandtype)
$CMD_DISPLAY_TOPOLOGY  = 100000020
$CMD_FACILITY_SETMODE  = 100000021
$CMD_FACILITY_POWERON  = 100000022
$CMD_FACILITY_POWEROFF = 100000023

# Step 5 discrete facility commands
$CMD_SETLIGHTS        = 100000024
$CMD_PROJECTOR_POWER  = 100000025
$CMD_AUDIO_VOLUME     = 100000026
$CMD_EMERGENCY_STOP   = 100000027


# Tracks the process started for Session Display so EndSession/Reset can close the right window
$Global:SessionDisplayProcId = $null

# Emergency stop latch (cleared only by explicit command)
$Global:EmergencyStopEngaged = $false
$Global:EmergencyStopReason = $null



$Global:SessionDisplayUrl = $null
$Global:SessionDisplayStatePath = "C:\AllBirdies\SessionDisplay\data\session-display.state.json"

$Global:SessionDisplayProfileDir = "C:\AllBirdies\SessionDisplay\edge-profile"
$Global:SessionDisplayTag = "--user-data-dir=$Global:SessionDisplayProfileDir"
# ---------------- Token cache ----------------
$Global:AccessToken = $null
$Global:TokenExpiresUtc = [DateTime]::MinValue

function Read-WebExceptionBody {
    param([Parameter(Mandatory=$true)]$WebException)
    try {
        $resp = $WebException.Response
        if ($resp -ne $null) {
            $stream = $resp.GetResponseStream()
            if ($stream -ne $null) {
                $reader = New-Object System.IO.StreamReader($stream)
                $body = $reader.ReadToEnd()
                $reader.Close()
                return $body
            }
        }
    } catch {}
    return $null
}

function Acquire-Token {
    $tokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $scope = "$OrgUrl/.default"

    $clientSecret = Get-ClientSecret

    $body = @(
        "client_id=$([uri]::EscapeDataString($ClientId))"
        "client_secret=$([uri]::EscapeDataString($clientSecret))"
        "grant_type=client_credentials"
        "scope=$([uri]::EscapeDataString($scope))"
    ) -join "&"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($body)

    $req = [System.Net.HttpWebRequest]::Create($tokenUrl)
    $req.Method = "POST"
    $req.ContentType = "application/x-www-form-urlencoded"
    $req.Accept = "application/json"
    $req.Timeout = 30000
    $req.ReadWriteTimeout = 30000

    $reqStream = $req.GetRequestStream()
    $reqStream.Write($bytes, 0, $bytes.Length)
    $reqStream.Close()

    $resp = $null
    $statusCode = $null
    $respText = $null

    try {
        $resp = $req.GetResponse()
        $statusCode = [int]$resp.StatusCode
    }
    catch [System.Net.WebException] {
        $resp = $_.Exception.Response
        if ($resp -ne $null) {
            try { $statusCode = [int]$resp.StatusCode } catch {}
            $respText = Read-WebExceptionBody -WebException $_.Exception
        }
    }

    if ($resp -ne $null -and -not $respText) {
        try {
            $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
            $respText = $reader.ReadToEnd()
            $reader.Close()
        } catch {}
    }

    if ($statusCode -lt 200 -or $statusCode -ge 300) {
        if ([string]::IsNullOrWhiteSpace($respText)) { $respText = "<empty>" }
        Write-Log "Token failed (HTTP $statusCode). Body: $respText" "ERROR"
        throw "Token request failed with HTTP $statusCode"
    }

    $json = $respText | ConvertFrom-Json
    if (-not $json.access_token) {
        Write-Log "Token success but missing access_token. Raw: $respText" "ERROR"
        throw "No access_token in token response."
    }

    # Cache expiry with a 5-minute safety buffer
    $expiresIn = 3600
    try { if ($json.expires_in) { $expiresIn = [int]$json.expires_in } } catch {}
    $Global:AccessToken = $json.access_token
    $Global:TokenExpiresUtc = (Get-Date).ToUniversalTime().AddSeconds($expiresIn - 300)

    Write-Log "Token acquired; expires approx $($Global:TokenExpiresUtc.ToString('yyyy-MM-ddTHH:mm:ssZ'))" "DEBUG"
    return $Global:AccessToken
}

function Get-AccessToken {
    $now = (Get-Date).ToUniversalTime()
    if ($Global:AccessToken -and $now -lt $Global:TokenExpiresUtc) { return $Global:AccessToken }
    return (Acquire-Token)
}

# ---------------- Dataverse HTTP helpers ----------------
function New-DvHeaders {
    param(
        [Parameter(Mandatory=$true)][string]$token,
        [string]$ifMatch = $null
    )

    $h = @{
        Authorization      = "Bearer $token"
        Accept             = "application/json"
        "OData-MaxVersion" = "4.0"
        "OData-Version"    = "4.0"
        "User-Agent"       = "ABG-BayAgent/$AgentVersion"
        Prefer             = 'odata.include-annotations="*"'
    }
    if ($ifMatch) { $h["If-Match"] = $ifMatch }
    return $h
}

function Invoke-DvSafe {
    param(
        [Parameter(Mandatory=$true)][ValidateSet("GET","PATCH")][string]$Method,
        [Parameter(Mandatory=$true)][string]$Uri,
        [Parameter(Mandatory=$true)][hashtable]$Headers,
        [string]$BodyJson = $null
    )

    try {
        if ($Method -eq "PATCH") {
            Invoke-RestMethod -Method Patch -Uri $Uri -Headers $Headers -ContentType "application/json" -Body $BodyJson -ErrorAction Stop | Out-Null
            return $null
        } else {
            return Invoke-RestMethod -Method Get -Uri $Uri -Headers $Headers -ErrorAction Stop
        }
    }
    catch {
        $ex = $_.Exception
        Write-Log "Dataverse call failed: $Method $Uri :: $($ex.Message)" "ERROR"

        # Best-effort: read Dataverse error JSON body
        try {
            $resp = $ex.Response
            if ($resp -ne $null) {
                $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
                $body = $reader.ReadToEnd()
                $reader.Close()
                if ($body) { Write-Log "Dataverse response body: $body" "ERROR" }
            }
        } catch {}

        throw
    }
}

function Dataverse-WhoAmI {
    param([Parameter(Mandatory=$true)][string]$token)
    $uri = "$OrgUrl/api/data/v9.2/WhoAmI()"
    $res = Invoke-DvSafe -Method GET -Uri $uri -Headers (New-DvHeaders $token)
    Write-Log ("WhoAmI OK: UserId={0} OrgId={1} BU={2}" -f $res.UserId, $res.OrganizationId, $res.BusinessUnitId) "INFO"
}

function Patch-Row {
    param(
        [Parameter(Mandatory=$true)][string]$token,
        [Parameter(Mandatory=$true)][string]$entitySet,
        [Parameter(Mandatory=$true)][string]$id,
        [Parameter(Mandatory=$true)]$bodyObj,
        [Parameter(Mandatory=$true)][string]$ifMatch
    )

    $id = ($id.ToString()).Trim("{}")
    $uri = "$OrgUrl/api/data/v9.2/$entitySet($id)"
    $json = ($bodyObj | ConvertTo-Json -Depth 10)

    Invoke-DvSafe -Method PATCH -Uri $uri -Headers (New-DvHeaders $token $ifMatch) -BodyJson $json
}


# ---------------- Step 8.2: Dynamic config pull + overlay + caching ----------------
$Global:NextConfigRefreshUtc = [DateTime]::MinValue
$Global:EffectiveConfig = $null

# Capabilities write-back cadence (seconds)
$Global:CapabilitiesEverySeconds = 600   # 10 minutes
$Global:NextCapabilitiesUtc = (Get-Date).ToUniversalTime()  # write on first heartbeat

function Dv-Get {
    param(
        [Parameter(Mandatory=$true)][string]$token,
        [Parameter(Mandatory=$true)][string]$pathAndQuery
    )
    $uri = "$OrgUrl/api/data/v9.2/$pathAndQuery"
    return Invoke-DvSafe -Method GET -Uri $uri -Headers (New-DvHeaders $token)
}

function Set-PSObjectProp {
    param(
        [Parameter(Mandatory=$true)]$obj,
        [Parameter(Mandatory=$true)][string]$name,
        $value
    )
    if ($null -eq $obj) { return }
    if ($obj.PSObject.Properties.Name -contains $name) {
        $obj.$name = $value
    } else {
        $obj | Add-Member -NotePropertyName $name -NotePropertyValue $value -Force
    }
}

function Get-EffectiveConfigValue {
    param(
        [hashtable]$cfg,
        [string]$key,
        $defaultValue = $null
    )
    if ($null -ne $cfg -and $cfg.ContainsKey($key)) {
        $v = $cfg[$key]
        if ($null -ne $v -and (-not [string]::IsNullOrWhiteSpace([string]$v))) { return $v }
    }
    return $defaultValue
}

function Get-BayContextForConfig {
    param([Parameter(Mandatory=$true)][string]$token)

    $selectBay = @(
        $Lookup_LocationValue,
        $Lookup_BayProfileValue,
        $Col_AgentStatus,
        $Col_AgentStatusUntil,
        $Col_AgentStatusReason
    ) -join ","

    $bay = Dv-Get $token "${BayEntitySet}($BayId)?`$select=$selectBay"

    $locId = $null
    $bpId  = $null
    try { $locId = $bay.$Lookup_LocationValue } catch {}
    try { $bpId  = $bay.$Lookup_BayProfileValue } catch {}

    $tzId = $null
    if ($locId) {
        $loc = Dv-Get $token "${LocationEntitySet}($locId)?`$select=$Col_TimeZoneId"
        try { $tzId = $loc.$Col_TimeZoneId } catch {}
    }

    $bp = $null
    if ($bpId) {
        $selectBp = @(
            $Col_BP_LauncherPath,
            $Col_BP_LauncherArgs,
            $Col_BP_LauncherProcName,
            $Col_BP_SessionMode,
            $Col_BP_SessionJsonPath,
            $Col_BP_ProfileJson
        ) -join ","
        $bp = Dv-Get $token "${BayProfileEntitySet}($bpId)?`$select=$selectBp"
    }

    return [pscustomobject]@{
        Bay = $bay
        LocationId = $locId
        TimeZoneId = $tzId
        BayProfileId = $bpId
        BayProfile = $bp
    }
}

function Get-ConfigOverlay {
    param(
        [Parameter(Mandatory=$true)][string]$token,
        [Parameter(Mandatory=$true)][Guid]$bayGuid,
        [Guid]$locationGuid = $null
    )

    # enabled AND (global OR location-match OR bay-match)
    $filter = "$Col_CI_Enabled eq true and ( $Col_CI_Scope eq $SCOPE_GLOBAL"
    if ($locationGuid) { $filter += " or ($Col_CI_Scope eq $SCOPE_LOCATION and _build_location_value eq $locationGuid)" }
    $filter += " or ($Col_CI_Scope eq $SCOPE_BAY and _build_bay_value eq $bayGuid) )"

    $select = "$Col_CI_Scope,$Col_CI_Key,$Col_CI_Value"
    $uri = "${ConfigItemEntitySet}?`$select=$select&`$filter=$([uri]::EscapeDataString($filter))&`$top=5000"

    $res = Dv-Get $token $uri
    $items = @()
    if ($res.value) { $items = @($res.value) }

    # order by precedence: Global -> Location -> Bay
    $ordered = @()
    $ordered += $items | Where-Object { $_.$Col_CI_Scope -eq $SCOPE_GLOBAL }
    $ordered += $items | Where-Object { $_.$Col_CI_Scope -eq $SCOPE_LOCATION }
    $ordered += $items | Where-Object { $_.$Col_CI_Scope -eq $SCOPE_BAY }

    $cfg = @{}
    foreach ($it in $ordered) {
        $k = $it.$Col_CI_Key
        if ([string]::IsNullOrWhiteSpace([string]$k)) { continue }
        $cfg[$k.Trim()] = $it.$Col_CI_Value
    }
    return $cfg
}

function Build-EffectiveConfig {
    param(
        [Parameter(Mandatory=$true)]$ctx,
        [Parameter(Mandatory=$true)][hashtable]$overlay
    )

    $eff = @{}

    if (-not [string]::IsNullOrWhiteSpace([string]$ctx.TimeZoneId)) {
        $eff["Location.TimeZoneId"] = $ctx.TimeZoneId
    }

    if ($ctx.BayProfile) {
        $bp = $ctx.BayProfile
        $eff["BayProfile.Id"] = $ctx.BayProfileId

        $eff["Bay.Launcher.Path"]        = $bp.$Col_BP_LauncherPath
        $eff["Bay.Launcher.Args"]        = $bp.$Col_BP_LauncherArgs
        $eff["Bay.Launcher.ProcessName"] = $bp.$Col_BP_LauncherProcName

        $eff["Bay.SessionDisplay.Mode"] = $bp.$Col_BP_SessionMode
        $eff["Bay.SessionDisplay.SessionJsonPath"] = $bp.$Col_BP_SessionJsonPath

        try {
            if ($bp.PSObject.Properties.Name -contains $Col_BP_ProfileJson) {
                $eff["BayProfile.ProfileJson"] = $bp.$Col_BP_ProfileJson
            }
        } catch {}
    }

    # overlay (Global -> Location -> Bay)
    foreach ($k in $overlay.Keys) { $eff[$k] = $overlay[$k] }

    # include operational status (read-only reference for Step 8.3)
    try { $eff["Bay.AgentStatus"] = $ctx.Bay.$Col_AgentStatus } catch {}
    try { $eff["Bay.AgentStatusUntil"] = $ctx.Bay.$Col_AgentStatusUntil } catch {}
    try { $eff["Bay.AgentStatusReason"] = $ctx.Bay.$Col_AgentStatusReason } catch {}

    return $eff
}

function Apply-EffectiveConfigToRuntime {
    param([Parameter(Mandatory=$true)][hashtable]$eff)

    # Poll / heartbeat / log level
    $newPoll = Get-EffectiveConfigValue $eff "Bay.PollSeconds" $script:PollSec
    $newHb   = Get-EffectiveConfigValue $eff "Bay.HeartbeatSeconds" $script:HeartbeatSec
    $newLvl  = Get-EffectiveConfigValue $eff "Bay.LogLevel" $Global:LogLevel

    try { $script:PollSec = [int]$newPoll } catch {}
    try { $script:HeartbeatSec = [int]$newHb } catch {}
    if ($script:HeartbeatSec -lt 15) { $script:HeartbeatSec = 15 }

    if (-not [string]::IsNullOrWhiteSpace([string]$newLvl)) {
        $Global:LogLevel = $newLvl.ToString().ToUpperInvariant()
    }

    # Launcher defaults (update $cfg so existing code paths keep working unchanged)
    if ($null -eq $cfg.launcher) { Set-PSObjectProp $cfg "launcher" ([pscustomobject]@{}) }
    $lp = Get-EffectiveConfigValue $eff "Bay.Launcher.Path" $null
    $la = Get-EffectiveConfigValue $eff "Bay.Launcher.Args" $null
    $ln = Get-EffectiveConfigValue $eff "Bay.Launcher.ProcessName" $null
    if ($lp) { Set-PSObjectProp $cfg.launcher "path" $lp }
    if ($la -ne $null) { Set-PSObjectProp $cfg.launcher "args" $la }
    if ($ln) { Set-PSObjectProp $cfg.launcher "processName" $ln }

    # Session display defaults (update $cfg so UpdateSessionDisplay / Start/End session uses it)
    $sj = Get-EffectiveConfigValue $eff "Bay.SessionDisplay.SessionJsonPath" $null
    if ($sj) { Set-PSObjectProp $cfg "sessionJsonPath" $sj }

    if ($null -eq $cfg.sessionDisplay) { Set-PSObjectProp $cfg "sessionDisplay" ([pscustomobject]@{}) }
    $sm = Get-EffectiveConfigValue $eff "Bay.SessionDisplay.Mode" $null
    if ($sm) {
        # Normalize SessionDisplay.Mode:
        # - BayProfile choice values come through as integers (e.g., 100000000)
        # - ConfigItem overrides may come through as "kiosk"/"normal"
        $smNorm = "$sm".ToLowerInvariant()
        switch ($smNorm) {
            "100000000" { $smNorm = "kiosk" }
            "100000001" { $smNorm = "normal" }
            "kiosk"     { $smNorm = "kiosk" }
            "normal"    { $smNorm = "normal" }
            default     { }
        }
        Set-PSObjectProp $cfg.sessionDisplay "mode" $smNorm
        # Also normalize the effective config value so later reads/logs see the label
        $eff["Bay.SessionDisplay.Mode"] = $smNorm
    }
    # Optional: log a one-line summary when config applies (DEBUG)
    if ($Global:LogLevel -eq "DEBUG") {
        $tz = Get-EffectiveConfigValue $eff "Location.TimeZoneId" "<null>"
        Write-Log ("[CFG] tz={0} poll={1}s hb={2}s launcher={3} sessionJson={4} mode={5}" -f $tz, $script:PollSec, $script:HeartbeatSec,
            (Get-EffectiveConfigValue $eff "Bay.Launcher.Path" "<null>"),
            (Get-EffectiveConfigValue $eff "Bay.SessionDisplay.SessionJsonPath" "<null>"),
            (Get-EffectiveConfigValue $eff "Bay.SessionDisplay.Mode" "<null>")
        ) "DEBUG"
    }
}

function Refresh-EffectiveConfigIfDue {
    param([Parameter(Mandatory=$true)][string]$token)

    $now = (Get-Date).ToUniversalTime()
    if ($now -lt $Global:NextConfigRefreshUtc -and $Global:EffectiveConfig) { return }

    try {
        $ctx = Get-BayContextForConfig $token

        $bayGuid = [Guid]$BayId
        $locGuid = $null
        if ($ctx.LocationId) { $locGuid = [Guid]$ctx.LocationId }

        $overlay = Get-ConfigOverlay -token $token -bayGuid $bayGuid -locationGuid $locGuid
        $eff = Build-EffectiveConfig -ctx $ctx -overlay $overlay

        $Global:EffectiveConfig = $eff
        Apply-EffectiveConfigToRuntime $eff

        $Global:NextConfigRefreshUtc = $now.AddSeconds($ConfigRefreshSec)
    }
    catch {
        # Don't crash on config failures; keep last-known-good config and retry soon
        Write-Log ("Dynamic config refresh failed: {0}" -f $_.Exception.Message) "WARN"
        $Global:NextConfigRefreshUtc = $now.AddSeconds([Math]::Min($ConfigRefreshSec, 30))
    }
}

function Build-AgentCapabilitiesJson {
    param(
        [Parameter(Mandatory=$true)][hashtable]$eff
    )

    # NOTE: Do NOT rely on $script:* vars here. This agent keeps runtime config in $cfg (agent-config.json),
    # and Step 8.2 overlays also populate $eff (BayProfile + ConfigItems). Use both safely.

    # Launcher
    $launcherPath = Get-EffectiveConfigValue $eff "Bay.Launcher.Path" $null
    if (-not $launcherPath -and $cfg -and $cfg.launcher) { $launcherPath = $cfg.launcher.path }

    $launcherProc = Get-EffectiveConfigValue $eff "Bay.Launcher.ProcessName" $null
    if (-not $launcherProc -and $cfg -and $cfg.launcher) { $launcherProc = $cfg.launcher.processName }

    # Session display
    $sessionJson = Get-EffectiveConfigValue $eff "Bay.SessionDisplay.SessionJsonPath" $null
    if (-not $sessionJson -and $cfg) { $sessionJson = $cfg.sessionJsonPath }

    $mode = Get-EffectiveConfigValue $eff "Bay.SessionDisplay.Mode" $null
    if (-not $mode -and $cfg -and $cfg.sessionDisplay) { $mode = $cfg.sessionDisplay.mode }

    $cap = [ordered]@{
        agentVersion    = $AgentVersion
        machineName     = $env:COMPUTERNAME
        lastUpdatedUtc  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

        launcher = @{
            path        = $launcherPath
            processName = $launcherProc
            pathExists  = ([string]::IsNullOrWhiteSpace([string]$launcherPath) -eq $false -and (Test-Path -LiteralPath $launcherPath))
        }

        sessionDisplay = @{
            mode            = $mode
            sessionJsonPath = $sessionJson
            jsonPathExists  = ([string]::IsNullOrWhiteSpace([string]$sessionJson) -eq $false -and (Test-Path -LiteralPath $sessionJson))
        }

        # Keep this conservative; expand as you add commands.
        supportedCommandTypes = @(
            "HealthCheck",
            "StartSession",
            "EndSession"
        )
    }

    return ($cap | ConvertTo-Json -Depth 6 -Compress)
}

# ---------------- Heartbeat (periodic) ----------------
$Global:NextHeartbeatUtc = [DateTime]::MinValue

function Send-HeartbeatIfDue {
    param(
        [Parameter(Mandatory=$true)][string]$token
    )

    $now = (Get-Date).ToUniversalTime()
    if ($now -lt $Global:NextHeartbeatUtc) { return }

    $nowUtcStr = $now.ToString("yyyy-MM-ddTHH:mm:ssZ")

    try {
        $patch = @{
            $Col_Heartbeat = $nowUtcStr
            $Col_Machine   = $env:COMPUTERNAME
            $Col_Version   = $AgentVersion
        }

        # Capabilities write-back (every N seconds)
        if ($now -ge $Global:NextCapabilitiesUtc) {
            try {
                $capJson = Build-AgentCapabilitiesJson -eff $(if ($Global:EffectiveConfig) { $Global:EffectiveConfig } else { @{} })
                $patch["build_agentcapabilitiesjson"] = $capJson

                # schedule next capabilities write
                $Global:NextCapabilitiesUtc = $now.AddSeconds($Global:CapabilitiesEverySeconds)

                if ($Global:LogLevel -eq "DEBUG") {
                    Write-Log ("Capabilities updated (next in {0}s)" -f $Global:CapabilitiesEverySeconds) "DEBUG"
                }
            }
            catch {
                # Never let capabilities block heartbeat; just retry soon
                Write-Log ("Capabilities update failed: {0}" -f $_.Exception.Message) "WARN"
                $Global:NextCapabilitiesUtc = $now.AddSeconds(30)
            }
        }

        Patch-Row $token "${BayEntitySet}" $BayId $patch "*"

        $Global:NextHeartbeatUtc = $now.AddSeconds($HeartbeatSec)
        Write-Log "Heartbeat updated ($nowUtcStr)" "DEBUG"
    }
    catch {
        # Don't crash the agent for heartbeat failures; just retry soon
        Write-Log "Heartbeat update failed: $($_.Exception.Message)" "WARN"
        $Global:NextHeartbeatUtc = $now.AddSeconds([Math]::Min($HeartbeatSec, 30))
    }
}


# ---------------- Step 8.3: Mode enforcement (Offline / Maintenance) ----------------
function Get-AgentOperationalState {
    param([Parameter(Mandatory=$true)][hashtable]$eff)

    $status = $AGENTSTATUS_ONLINE
    try { $status = [int](Get-EffectiveConfigValue $eff "Bay.AgentStatus" $AGENTSTATUS_ONLINE) } catch {}

    $reason = ""
    try { $reason = [string](Get-EffectiveConfigValue $eff "Bay.AgentStatusReason" "") } catch {}

    $untilRaw = $null
    try { $untilRaw = Get-EffectiveConfigValue $eff "Bay.AgentStatusUntil" $null } catch {}

    $untilUtc = $null
    if (-not [string]::IsNullOrWhiteSpace([string]$untilRaw)) {
        try { $untilUtc = [DateTime]::Parse([string]$untilRaw).ToUniversalTime() } catch {}
    }

    $now = (Get-Date).ToUniversalTime()
    $expired = ($untilUtc -ne $null -and $untilUtc -le $now)

    $modeLabel = switch ($status) {
        $AGENTSTATUS_OFFLINE     { "Offline" }
        $AGENTSTATUS_MAINTENANCE { "Maintenance" }
        $AGENTSTATUS_DEGRADED    { "Degraded" }
        default                  { "Online" }
    }

    $blocked = ($status -eq $AGENTSTATUS_OFFLINE -or $status -eq $AGENTSTATUS_MAINTENANCE)

    # If a temporary block has expired, treat as unblocked (and we’ll auto-clear the fields below)
    if ($blocked -and $expired) { $blocked = $false }

    $blockReason = ""
    if ($status -eq $AGENTSTATUS_OFFLINE -or $status -eq $AGENTSTATUS_MAINTENANCE) {
        $blockReason = ("Bay is in {0} mode{1}" -f $modeLabel, ($(if (-not [string]::IsNullOrWhiteSpace($reason)) { ": $reason" } else { "" })))
        if ($untilUtc -ne $null) { $blockReason += (" (until {0}Z)" -f $untilUtc.ToString("yyyy-MM-ddTHH:mm:ss")) }
    }

    return [pscustomobject]@{
        Status      = $status
        ModeLabel   = $modeLabel
        Blocked     = $blocked
        Expired     = $expired
        UntilUtc    = $untilUtc
        Reason      = $reason
        BlockReason = $blockReason
    }
}

function Is-CommandAllowedInMode {
    param(
        [Parameter(Mandatory=$true)][int]$CommandType,
        [Parameter(Mandatory=$true)]$OpState
    )

    if (-not $OpState -or -not $OpState.Blocked) { return $true }

    # OFFLINE: allow only safe “read-only / diagnostics” style commands
    if ($OpState.Status -eq $AGENTSTATUS_OFFLINE) {
        return (
            $CommandType -eq $CMD_HEALTHCHECK -or
            $CommandType -eq $CMD_SHOWMESSAGE -or
            $CommandType -eq $CMD_QUERYPROCESS -or
            $CommandType -eq $CMD_DISPLAY_TOPOLOGY
        )
    }

    # MAINTENANCE: allow operator controls, but block customer session starts
    if ($OpState.Status -eq $AGENTSTATUS_MAINTENANCE) {
        return ($CommandType -ne $CMD_STARTSESSION)
    }

    return $true
}

function AutoClear-ExpiredAgentStatusIfDue {
    param([Parameter(Mandatory=$true)][string]$token)

    if (-not $Global:EffectiveConfig) { return }

    $op = Get-AgentOperationalState -eff $Global:EffectiveConfig
    if (-not $op.Expired) { return }

    # Only auto-clear if we were in a blocking mode and the Until has elapsed
    if ($op.Status -ne $AGENTSTATUS_OFFLINE -and $op.Status -ne $AGENTSTATUS_MAINTENANCE) { return }

    try {
        Patch-Row $token "${BayEntitySet}" $BayId @{
            $Col_AgentStatus       = $AGENTSTATUS_ONLINE
            $Col_AgentStatusUntil  = $null
            $Col_AgentStatusReason = $null
        } "*"

        Write-Log ("AgentStatusUntil expired; auto-cleared {0} -> Online" -f $op.ModeLabel) "INFO"

        # Force a config refresh next loop so EffectiveConfig reflects the cleared status
        $Global:NextConfigRefreshUtc = (Get-Date).ToUniversalTime()
    }
    catch {
        Write-Log ("Failed to auto-clear expired AgentStatus: {0}" -f $_.Exception.Message) "WARN"
    }
}

# ---------------- Command polling ----------------
function Get-NextPendingCommand {
    param([Parameter(Mandatory=$true)][string]$token)

    $nowUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $selectClause = "$Col_CommandId,$Col_Status,$Col_CommandType,$Col_Payload,$Col_AttemptCount,$Col_NotBefore,createdon,$Lookup_BayValue"

    $filterClause = "$Lookup_BayValue eq $BayId and $Col_Status eq $STATUS_PENDING and ($Col_NotBefore eq null or $Col_NotBefore le $nowUtc)"

    $uri = "$OrgUrl/api/data/v9.2/${BayCommandEntitySet}?`$select=$selectClause&`$filter=$([uri]::EscapeDataString($filterClause))&`$orderby=createdon asc&`$top=1"
    $res = Invoke-DvSafe -Method GET -Uri $uri -Headers (New-DvHeaders $token)
    if ($res.value -and $res.value.Count -gt 0) { return $res.value[0] }
    return $null
}

# ---------------- Command execution ----------------
function Try-ParseJson([string]$jsonText) {
    if ([string]::IsNullOrWhiteSpace($jsonText)) { return $null }
    try { return ($jsonText | ConvertFrom-Json) } catch { return $null }
}

function Get-PropValue($obj, [string]$name, $default = $null) {
    if ($null -eq $obj) { return $default }

    # Hashtable / dictionary
    if ($obj -is [System.Collections.IDictionary]) {
        foreach ($k in $obj.Keys) { if ($k -ieq $name) { return $obj[$k] } }
        return $default
    }

    # PSCustomObject or other PSObject
    try {
        foreach ($p in $obj.PSObject.Properties) {
            if ($p.Name -ieq $name) { return $p.Value }
        }
    } catch {}
    return $default
}


function Set-PropValue {
    param(
        [Parameter(Mandatory=$true)]$obj,
        [Parameter(Mandatory=$true)][string]$name,
        $value,
        [switch]$OnlyIfMissing
    )
    if ($null -eq $obj) { return }

    $existing = Get-PropValue $obj $name $null
    if ($OnlyIfMissing -and $null -ne $existing -and -not [string]::IsNullOrWhiteSpace([string]$existing)) { return }

    if ($obj -is [System.Collections.IDictionary]) {
        # Hashtable/dictionary
        $obj[$name] = $value
        return
    }

    # PSObject: update if exists, else add
    try {
        foreach ($p in $obj.PSObject.Properties) {
            if ($p.Name -ieq $name) {
                $p.Value = $value
                return
            }
        }
        $obj | Add-Member -NotePropertyName $name -NotePropertyValue $value -Force
    } catch {
        # no-op
    }
}

function Get-BayLabelFromCommandRow {
    param([Parameter(Mandatory=$true)]$cmdRow)

    # Dataverse lookup formatted value is typically:
    #   _build_bay_value@OData.Community.Display.V1.FormattedValue : "Bay_1"
    $fmtProp = "$Lookup_BayValue@OData.Community.Display.V1.FormattedValue"
    $label = Get-PropValue $cmdRow $fmtProp $null

    if ([string]::IsNullOrWhiteSpace([string]$label)) {
        # Sometimes clients use build_bay@... formatted value (less common for lookups)
        $altProp = "$Lookup_Bay@OData.Community.Display.V1.FormattedValue"
        $label = Get-PropValue $cmdRow $altProp $null
    }

    if ([string]::IsNullOrWhiteSpace([string]$label)) {
        # Fallback to config-defined label (if any) or "Bay"
        return (Get-BayLabel)
    }
    return $label.ToString()
}


function Get-DefaultEdgePath {
    $candidates = @(
        "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        "C:\Program Files\Microsoft\Edge\Application\msedge.exe"
    )
    foreach ($p in $candidates) { if (Test-Path $p) { return $p } }
    return "msedge.exe"
}

function Get-SessionJsonPath {
    $p = $null
    try {
        if ($cfg.PSObject.Properties.Name -contains "sessionJsonPath") { $p = $cfg.sessionJsonPath }
    } catch {}
    if ([string]::IsNullOrWhiteSpace([string]$p)) { $p = "C:\AllBirdies\SessionDisplay\data\session.json" }
    return $p
}


function Write-TextAtomic([string]$path, [string]$text) {
    $dir = Split-Path -Parent $path
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    $tmp = "$path.tmp"
    Set-Content -Path $tmp -Value $text -Encoding UTF8

    try {
        if (Test-Path $path) {
            # Atomic replace when the destination exists
            [System.IO.File]::Replace($tmp, $path, $null, $true)
        } else {
            Move-Item -Path $tmp -Destination $path -Force
        }
    } catch {
        # Fallback: best-effort overwrite
        if (Test-Path $path) { Remove-Item $path -Force }
        Move-Item -Path $tmp -Destination $path -Force
    }
}

function Write-JsonAtomic([string]$path, $obj) {
    $json = ($obj | ConvertTo-Json -Depth 10)
    Write-TextAtomic -path $path -text $json
}

function Get-SessionJsPath {
    $jsonPath = Get-SessionJsonPath
    # Same folder, different extension
    return ([System.IO.Path]::ChangeExtension($jsonPath, "js"))
}

function Write-SessionFiles($modelObj) {
    $jsonPath = Get-SessionJsonPath
    $jsPath   = Get-SessionJsPath

    # 1) Write JSON (for debugging / inspection)
    Write-JsonAtomic -path $jsonPath -obj $modelObj

    # 2) Write JS (avoids file:// fetch restrictions in some Edge/Chromium modes)
    $jsonCompact = ($modelObj | ConvertTo-Json -Depth 10 -Compress)
    $js = "window.ABG_SESSION = $jsonCompact;"
    Write-TextAtomic -path $jsPath -text $js

    return @{ sessionJsonPath = $jsonPath; sessionJsPath = $jsPath }
}


# ---------------- Session lifecycle helpers (Step 3) ----------------
function Get-BayLabel {
    try {
        if ($cfg.PSObject.Properties.Name -contains "bayLabel" -and -not [string]::IsNullOrWhiteSpace([string]$cfg.bayLabel)) {
            return $cfg.bayLabel.ToString()
        }
    } catch {}
    return "Bay"
}

function Get-HelpText {
    try {
        if ($cfg.PSObject.Properties.Name -contains "helpText" -and -not [string]::IsNullOrWhiteSpace([string]$cfg.helpText)) {
            return $cfg.helpText.ToString()
        }
    } catch {}
    return "Need help? Text us."
}

function Read-SessionModelFromDisk {
    # Reads the last written session model from session.json (preferred).
    $jsonPath = Get-SessionJsonPath
    if (Test-Path $jsonPath) {
        try {
            $raw = Get-Content -Path $jsonPath -Raw -Encoding UTF8
            if (-not [string]::IsNullOrWhiteSpace($raw)) {
                return ($raw | ConvertFrom-Json)
            }
        } catch {}
    }
    return $null
}

function To-Hashtable($obj) {
    if ($null -eq $obj) { return @{} }
    if ($obj -is [hashtable]) { return $obj }

    $ht = @{}
    try {
        foreach ($p in $obj.PSObject.Properties) {
            $ht[$p.Name] = $p.Value
        }
    } catch {}
    return $ht
}

function Merge-Hashtables([hashtable]$base, [hashtable]$patch) {
    $out = @{}
    foreach ($k in $base.Keys) { $out[$k] = $base[$k] }
    foreach ($k in $patch.Keys) { $out[$k] = $patch[$k] }
    return $out
}


function Normalize-SessionModel([hashtable]$model) {
    # Normalizes common fields so the Session Display and promo targeting are consistent:
    # - Keeps displayName/customerDisplayName/customer.displayName aligned
    # - Prefers bayLabel for display, falling back to locationLabel/config
    # - Ensures timing.startUtc/timing.endUtc matches sessionStartUtc/sessionEndUtc
    if ($null -eq $model) { return $model }

    # Bay label normalization
    $bayLabel = Get-PropValue $model "bayLabel" $null
    $locLabel = Get-PropValue $model "locationLabel" $null
    if (-not [string]::IsNullOrWhiteSpace([string]$bayLabel)) {
        if ([string]::IsNullOrWhiteSpace([string]$locLabel) -or $locLabel -eq "Bay") {
            $model.locationLabel = $bayLabel
        }
    }

    # Name normalization (prefer customerDisplayName, then displayName, then customer.displayName)
    $custObj = Get-PropValue $model "customer" $null
    $custHt = $null
    if ($null -ne $custObj) {
        try { $custHt = To-Hashtable $custObj } catch { $custHt = $null }
    }

    $name = Get-PropValue $model "customerDisplayName" $null
    if ([string]::IsNullOrWhiteSpace([string]$name)) { $name = Get-PropValue $model "displayName" $null }
    if ([string]::IsNullOrWhiteSpace([string]$name) -and $null -ne $custHt) { $name = Get-PropValue $custHt "displayName" $null }
    if ([string]::IsNullOrWhiteSpace([string]$name)) { $name = "Guest" }
    $model.displayName = $name
    $model.customerDisplayName = $name

    if ($null -eq $custHt) { $custHt = @{} }
    # Keep customer.displayName aligned with displayName/customerDisplayName (display UI prefers this field).
    $custHt.displayName = $name
    $model.customer = $custHt

    # Timing normalization
    $s = Get-PropValue $model "sessionStartUtc" $null
    if ([string]::IsNullOrWhiteSpace([string]$s)) { $s = Get-PropValue $model "startUtc" $null }
    $e = Get-PropValue $model "sessionEndUtc" $null
    # Prefer playEndUtc (customer-visible play end) when present
    if ([string]::IsNullOrWhiteSpace([string]$e)) { $e = Get-PropValue $model "playEndUtc" $null }
    if ([string]::IsNullOrWhiteSpace([string]$e)) { $e = Get-PropValue $model "endUtc" $null }

    $timingObj = Get-PropValue $model "timing" $null
    $timingHt = $null
    if ($null -ne $timingObj) {
        try { $timingHt = To-Hashtable $timingObj } catch { $timingHt = $null }
    }
    if ($null -eq $timingHt) { $timingHt = @{} }
    if (-not [string]::IsNullOrWhiteSpace([string]$s)) { $timingHt.startUtc = $s.ToString() }
    if (-not [string]::IsNullOrWhiteSpace([string]$e)) { $timingHt.endUtc = $e.ToString() }
    $model.timing = $timingHt

    # Schema + updatedUtc
    if ([string]::IsNullOrWhiteSpace([string](Get-PropValue $model "schema" $null))) { $model.schema = "abg.session.v1" }
    if ([string]::IsNullOrWhiteSpace([string](Get-PropValue $model "updatedUtc" $null))) { $model.updatedUtc = (UtcNow-Z) }

    return $model
}

function UtcNow-Z {
    return (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}

function Build-SessionDisplayPatchFromPayload($payloadObj) {
    # Accepts either:
    #  1) A "mode-based" session payload (Prep/Start/Warn5/End) from Power Automate
    #  2) A full display model (status/sessionEndUtc/etc.)
    #
    # Returns a hashtable patch that can be merged with the previous model.
    $p = $payloadObj

    $mode = Get-PropValue $p "mode" $null
    if (-not [string]::IsNullOrWhiteSpace([string]$mode)) { $mode = $mode.ToString() }

    $status = Get-PropValue $p "status" $null
    if ([string]::IsNullOrWhiteSpace([string]$status) -and -not [string]::IsNullOrWhiteSpace([string]$mode)) {
        switch ($mode.ToLowerInvariant()) {
            "prep"  { $status = "PREP" }
            "start" { $status = "ACTIVE" }
            "warn5" { $status = "ENDING" }
            "end"   { $status = "ENDED" }
            default { $status = $null }
        }
    }

    # Primary fields (support both naming conventions)
    $displayName = Get-PropValue $p "displayName" $null
    if ([string]::IsNullOrWhiteSpace([string]$displayName)) { $displayName = Get-PropValue $p "customerDisplayName" $null }
    if ([string]::IsNullOrWhiteSpace([string]$displayName)) { $displayName = "Guest" }

$locationLabel = Get-PropValue $p "locationLabel" $null
if ([string]::IsNullOrWhiteSpace([string]$locationLabel)) { $locationLabel = Get-PropValue $p "bayLabel" $null }
if ([string]::IsNullOrWhiteSpace([string]$locationLabel)) { $locationLabel = Get-BayLabel }

$bayLabel = Get-PropValue $p "bayLabel" $null
$bayId = Get-PropValue $p "bayId" $null

    $helpText = Get-PropValue $p "helpText" $null
    if ([string]::IsNullOrWhiteSpace([string]$helpText)) { $helpText = Get-HelpText }

    # Times: allow either sessionStartUtc/sessionEndUtc OR startUtc/endUtc
    $startUtc = Get-PropValue $p "sessionStartUtc" $null
    if ([string]::IsNullOrWhiteSpace([string]$startUtc)) { $startUtc = Get-PropValue $p "startUtc" $null }

    $endUtc = Get-PropValue $p "sessionEndUtc" $null
    # Prefer playEndUtc (customer-visible play end) when present
    if ([string]::IsNullOrWhiteSpace([string]$endUtc)) { $endUtc = Get-PropValue $p "playEndUtc" $null }
    if ([string]::IsNullOrWhiteSpace([string]$endUtc)) { $endUtc = Get-PropValue $p "endUtc" $null }

    # Banner/message
    $bannerText = Get-PropValue $p "bannerText" $null
    if ([string]::IsNullOrWhiteSpace([string]$bannerText)) { $bannerText = Get-PropValue $p "message" $null }

    if ([string]::IsNullOrWhiteSpace([string]$bannerText) -and -not [string]::IsNullOrWhiteSpace([string]$mode)) {
        switch ($mode.ToLowerInvariant()) {
            "prep"  { $bannerText = "" }
            "start" { $bannerText = "" }
            "warn5" { $bannerText = "5 minutes remaining" }
            "end"   { $bannerText = "Session ended" }
        }
    }

    $patch = @{}
    if (-not [string]::IsNullOrWhiteSpace([string]$status)) { $patch.status = $status.ToString().ToUpperInvariant() }
    if (-not [string]::IsNullOrWhiteSpace([string]$locationLabel)) { $patch.locationLabel = $locationLabel }
    if (-not [string]::IsNullOrWhiteSpace([string]$bayLabel)) { $patch.bayLabel = $bayLabel }
    if (-not [string]::IsNullOrWhiteSpace([string]$bayId)) { $patch.bayId = $bayId }
    if (-not [string]::IsNullOrWhiteSpace([string]$displayName)) { $patch.displayName = $displayName }
    if ($null -ne $startUtc -and -not [string]::IsNullOrWhiteSpace([string]$startUtc)) { $patch.sessionStartUtc = $startUtc.ToString() }
    if ($null -ne $endUtc -and -not [string]::IsNullOrWhiteSpace([string]$endUtc)) { $patch.sessionEndUtc = $endUtc.ToString() }
    if ($null -ne $bannerText) { $patch.bannerText = $bannerText.ToString() }
    if (-not [string]::IsNullOrWhiteSpace([string]$helpText)) { $patch.helpText = $helpText }

    # Copy identifiers for debugging (optional)
    $baySessionId = Get-PropValue $p "baySessionId" $null
    if (-not [string]::IsNullOrWhiteSpace([string]$baySessionId)) { $patch.baySessionId = $baySessionId.ToString() }

    $bookingId = Get-PropValue $p "bookingId" $null
    if (-not [string]::IsNullOrWhiteSpace([string]$bookingId)) { $patch.bookingId = $bookingId.ToString() }

    $patch.updatedUtc = (UtcNow-Z)
    return $patch
}

function Get-LauncherConfigFromPayloadOrConfig($payloadObj) {
    # Payload override: payload.launcher.path/args/processName
    $pl = Get-PropValue $payloadObj "launcher" $null
    $path = Get-PropValue $pl "path" $null
    $args = Get-PropValue $pl "args" $null
    $procName = Get-PropValue $pl "processName" $null
    $startOnPrep = Get-PropValue $pl "startOnPrep" $null
    $startOnStart = Get-PropValue $pl "startOnStart" $null

    # Fallback to config.launcher.*
    if ([string]::IsNullOrWhiteSpace([string]$path)) {
        $cl = $null
        try { $cl = $cfg.launcher } catch { $cl = $null }
        $path = Get-PropValue $cl "path" $path
        $args = Get-PropValue $cl "args" $args
        $procName = Get-PropValue $cl "processName" $procName
        if ($null -eq $startOnPrep) { $startOnPrep = Get-PropValue $cl "startOnPrep" $null }
        if ($null -eq $startOnStart) { $startOnStart = Get-PropValue $cl "startOnStart" $null }
    }

    return @{
        path = $path
        args = $args
        processName = $procName
        startOnPrep = $startOnPrep
        startOnStart = $startOnStart
    }
}

function Start-LauncherIfNeeded([string]$context, $launcherCfg) {
    $path = $launcherCfg.path
    $args = $launcherCfg.args
    $processName = $launcherCfg.processName

    if ([string]::IsNullOrWhiteSpace([string]$path)) {
        return @{ started = $false; reason = "no_launcher_path_configured"; context = $context }
    }
    if (!(Test-Path $path)) {
        return @{ started = $false; reason = "launcher_path_not_found"; path = $path; context = $context }
    }

    # If processName is provided, don't start if already running
    if (-not [string]::IsNullOrWhiteSpace([string]$processName)) {
        $base = [System.IO.Path]::GetFileNameWithoutExtension([string]$processName)
        $running = Get-Process -Name $base -ErrorAction SilentlyContinue
        if ($running) {
            $pids = @($running | Select-Object -ExpandProperty Id)
            # Step 5: best-effort route already-running Launcher to the Control display
            try {
                $role = Get-PropValue $launcherCfg "displayRole" $null
                if ([string]::IsNullOrWhiteSpace([string]$role)) { $role = "control" }
                foreach ($id in $pids) { $null = Safe-RouteProcessWindow -context $context -pid ([int]$id) -role $role -payloadObj $null -Maximize }
            } catch {}
            return @{ started = $false; reason = "already_running"; processName = $base; pids = $pids; context = $context }
        }
    }

    $proc = $null
    if ([string]::IsNullOrWhiteSpace([string]$args)) {
        $proc = Start-Process -FilePath $path -PassThru
    } else {
        $proc = Start-Process -FilePath $path -ArgumentList $args -PassThru
    }
    # Step 5: route Launcher window to Control display (best effort)
    try {
        $role = Get-PropValue $launcherCfg "displayRole" $null
        if ([string]::IsNullOrWhiteSpace([string]$role)) { $role = "control" }
        $null = Safe-RouteProcessWindow -context $context -pid ([int]$proc.Id) -role $role -payloadObj $null -Maximize
    } catch {}

    return @{ started = $true; pid = $proc.Id; path = $path; args = $args; context = $context }
}

function Stop-AppsIfRequested($payloadObj) {
    $closeApps = [bool](Get-PropValue $payloadObj "closeApps" $false)
    if (-not $closeApps) { return @{ stopped = $false; reason = "closeApps_false" } }

    $apps = Get-PropValue $payloadObj "appsToClose" $null
    if ($null -eq $apps) { return @{ stopped = $true; reason = "no_apps_list"; closed = @() } }

    $closed = @()
    foreach ($a in $apps) {
        if ($null -eq $a) { continue }
        $name = $a.ToString()
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        $base = [System.IO.Path]::GetFileNameWithoutExtension($name)
        try {
            $procs = Get-Process -Name $base -ErrorAction SilentlyContinue
            if ($procs) {
                $pids = @($procs | Select-Object -ExpandProperty Id)
                $procs | Stop-Process -Force -ErrorAction SilentlyContinue
                $closed += @{ processName = $base; pids = $pids }
            }
        } catch {}
    }
    return @{ stopped = $true; closed = $closed }
}


# ---------------- Step 5: Display routing + facility controls ----------------
# This section is designed to be "hardware tolerant":
# - If a target display (projector/touch/TV) isn't present yet, routing gracefully falls back.
# - Facility device power control defaults to Simulated unless explicitly enabled/configured.

# Load WinForms for Screen enumeration (safe no-op if not available)
try { Add-Type -AssemblyName System.Windows.Forms } catch {}
try { Add-Type -AssemblyName System.Drawing } catch {}

# Win32 window helpers (EnumWindows, move/resize, etc.)
if (-not ("ABGWin32" -as [type])) {
Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;

public static class ABGWin32 {
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);
    [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);

    // Display device info
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct DISPLAY_DEVICE {
        public int cb;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=32)]
        public string DeviceName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=128)]
        public string DeviceString;
        public int StateFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=128)]
        public string DeviceID;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=128)]
        public string DeviceKey;
    }

    [DllImport("user32.dll", CharSet=CharSet.Unicode)]
    public static extern bool EnumDisplayDevices(string lpDevice, uint iDevNum, ref DISPLAY_DEVICE lpDisplayDevice, uint dwFlags);

    public const int SW_RESTORE  = 9;
    public const int SW_MAXIMIZE = 3;

    public const uint SWP_NOZORDER   = 0x0004;
    public const uint SWP_NOACTIVATE = 0x0010;
    public const uint SWP_SHOWWINDOW = 0x0040;

    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left; public int Top; public int Right; public int Bottom; }
}
"@
}

function Get-DisplayDeviceString([string]$deviceName) {
    # deviceName is typically like "\\.\DISPLAY1"
    try {
        $dd = New-Object ABGWin32+DISPLAY_DEVICE
        $dd.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($dd)
        # iDevNum=0 enumerates the first display attached to that name
        $ok = [ABGWin32]::EnumDisplayDevices($deviceName, 0, [ref]$dd, 0)
        if ($ok -and -not [string]::IsNullOrWhiteSpace([string]$dd.DeviceString)) {
            return $dd.DeviceString
        }
    } catch {}
    return $null
}

function Get-DisplayTopology {
    # Returns a stable-ish view of monitors for config + troubleshooting.
    $out = @()
    try {
        $screens = [System.Windows.Forms.Screen]::AllScreens
        for ($i=0; $i -lt $screens.Count; $i++) {
            $s = $screens[$i]
            $b = $s.Bounds
            $ds = Get-DisplayDeviceString $s.DeviceName
            $out += [ordered]@{
                index      = $i
                deviceName = $s.DeviceName
                deviceDesc = $ds
                primary    = [bool]$s.Primary
                left       = $b.Left
                top        = $b.Top
                width      = $b.Width
                height     = $b.Height
            }
        }
    } catch {
        $out += [ordered]@{ error = $_.Exception.Message }
    }
    return $out
}

function Get-DisplayRoutingConfigFromPayloadOrConfig($payloadObj) {
    # Prefer payload.displayRouting, then cfg.displayRouting, then cfg.facility.displayRouting
    $dr = Get-PropValue $payloadObj "displayRouting" $null
    if ($null -ne $dr) { return $dr }

    try {
        if ($cfg.PSObject.Properties.Name -contains "displayRouting") { return $cfg.displayRouting }
    } catch {}

    try {
        $fac = $cfg.facility
        if ($null -ne $fac) { return $fac.displayRouting }
    } catch {}

    return $null
}

function Resolve-RoleSelectorToScreen($selector, $screens) {
    if ($null -eq $screens) { $screens = [System.Windows.Forms.Screen]::AllScreens }
    if ($null -eq $selector) { return $null }

    # Numeric index
    try {
        if ($selector -is [int] -or $selector -is [long] -or ($selector -is [double])) {
            $idx = [int]$selector
            if ($idx -ge 0 -and $idx -lt $screens.Count) { return $screens[$idx] }
        }
    } catch {}

    $sel = $selector.ToString()
    if ([string]::IsNullOrWhiteSpace($sel)) { return $null }
    $sel = $sel.Trim()

    # DeviceName direct match
    foreach ($s in $screens) {
        if ($s.DeviceName -ieq $sel) { return $s }
    }

    # Allow shorthand like "DISPLAY2"
    if ($sel -match '^DISPLAY\d+$') {
        $full = "\\.\$sel"
        foreach ($s in $screens) {
            if ($s.DeviceName -ieq $full) { return $s }
        }
    }

    # Substring match on DeviceString (friendly-ish)
    foreach ($s in $screens) {
        $ds = Get-DisplayDeviceString $s.DeviceName
        if (-not [string]::IsNullOrWhiteSpace([string]$ds) -and $ds.ToLowerInvariant().Contains($sel.ToLowerInvariant())) {
            return $s
        }
    }

    return $null
}

function Get-ScreenForRole([string]$role, $payloadObj) {
    # Roles: play, control, session
    $screens = $null
    try { $screens = [System.Windows.Forms.Screen]::AllScreens } catch { return $null }

    $dr = Get-DisplayRoutingConfigFromPayloadOrConfig $payloadObj
    $enabled = $true
    try {
        $enabledVal = Get-PropValue $dr "enabled" $null
        if ($null -ne $enabledVal) { $enabled = [bool]$enabledVal }
    } catch {}
    if (-not $enabled) { return $null }

    # role selector from config/payload
    $roles = Get-PropValue $dr "roles" $null
    $roleObj = Get-PropValue $roles $role $null
    $selector = $null
    $selector = Get-PropValue $roleObj "selector" $null
    if ($null -eq $selector) { $selector = Get-PropValue $roleObj "deviceName" $null }
    if ($null -eq $selector) { $selector = Get-PropValue $roleObj "index" $null }

    $screen = $null
    if ($null -ne $selector) {
        $screen = Resolve-RoleSelectorToScreen $selector $screens
    }

    if ($null -ne $screen) { return $screen }

    # Safe fallbacks if not configured:
    # - play: primary
    # - control: first non-primary
    # - session: last non-primary (if 2+ monitors)
    if ($role -ieq "play") {
        foreach ($s in $screens) { if ($s.Primary) { return $s } }
        return $screens[0]
    }

    $nonPrimary = @($screens | Where-Object { -not $_.Primary })
    if ($nonPrimary.Count -eq 0) { return $null }

    if ($role -ieq "control") { return $nonPrimary[0] }
    if ($role -ieq "session") { return $nonPrimary[$nonPrimary.Count - 1] }

    return $null
}

function Get-FirstVisibleWindowHandleForPid([int]$pid) {
    # Returns the first visible top-level window for a PID, or IntPtr::Zero.
    $script:__abgFoundHwnd = [IntPtr]::Zero
    try {
        $cb = [ABGWin32+EnumWindowsProc]{
            param([IntPtr]$hWnd, [IntPtr]$lParam)
            try {
                if (-not [ABGWin32]::IsWindowVisible($hWnd)) { return $true }
                $outPid = 0
                [void][ABGWin32]::GetWindowThreadProcessId($hWnd, [ref]$outPid)
                if ([int]$outPid -eq $pid) {
                    $script:__abgFoundHwnd = $hWnd
                    return $false
                }
            } catch {}
            return $true
        }
        [void][ABGWin32]::EnumWindows($cb, [IntPtr]::Zero)
    } catch {}
    return $script:__abgFoundHwnd
}

function Move-ProcessWindowToRole {
    param(
        [Parameter(Mandatory=$true)][int]$pid,
        [Parameter(Mandatory=$true)][ValidateSet("play","control","session")][string]$role,
        $payloadObj,
        [int]$timeoutSec = 8,
        [switch]$Maximize
    )

    $screen = Get-ScreenForRole $role $payloadObj
    if ($null -eq $screen) { return @{ moved = $false; reason = "no_target_screen"; role = $role; pid = $pid } }

    $deadline = (Get-Date).AddSeconds($timeoutSec)
    $hWnd = [IntPtr]::Zero
    do {
        $hWnd = Get-FirstVisibleWindowHandleForPid $pid
        if ($hWnd -ne [IntPtr]::Zero) { break }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)

    if ($hWnd -eq [IntPtr]::Zero) {
        return @{ moved = $false; reason = "no_window_handle"; role = $role; pid = $pid }
    }

    $b = $screen.Bounds
    try {
        # Restore then move/resize then optionally maximize
        [void][ABGWin32]::ShowWindow($hWnd, [ABGWin32]::SW_RESTORE)
        [void][ABGWin32]::SetWindowPos($hWnd, [IntPtr]::Zero, $b.Left, $b.Top, $b.Width, $b.Height,
            [ABGWin32]::SWP_NOZORDER -bor [ABGWin32]::SWP_NOACTIVATE -bor [ABGWin32]::SWP_SHOWWINDOW)
        if ($Maximize) { [void][ABGWin32]::ShowWindow($hWnd, [ABGWin32]::SW_MAXIMIZE) }
        return @{
            moved = $true
            role = $role
            pid = $pid
            deviceName = $screen.DeviceName
            deviceDesc = (Get-DisplayDeviceString $screen.DeviceName)
            bounds = @{ left=$b.Left; top=$b.Top; width=$b.Width; height=$b.Height }
        }
    } catch {
        return @{ moved = $false; role = $role; pid = $pid; error = $_.Exception.Message }
    }
}

function Safe-RouteProcessWindow {
    param(
        [string]$context,
        [int]$pid,
        [string]$role,
        $payloadObj,
        [switch]$Maximize
    )
    try {
        $res = Move-ProcessWindowToRole -pid $pid -role $role -payloadObj $payloadObj -Maximize:$Maximize
        if ($res.moved) {
            Write-Log "DisplayRouting: moved pid=$pid to role=$role ($($res.deviceName) / $($res.deviceDesc)) context=$context" "INFO"
        } else {
            Write-Log "DisplayRouting: no move pid=$pid role=$role reason=$($res.reason) context=$context" "DEBUG"
        }
        return $res
    } catch {
        Write-Log "DisplayRouting: exception context=$context pid=$pid role=$role :: $($_.Exception.Message)" "WARN"
        return @{ moved = $false; role = $role; pid = $pid; error = $_.Exception.Message }
    }
}

function Get-FacilityConfigFromPayloadOrConfig($payloadObj) {
    $f = Get-PropValue $payloadObj "facility" $null
    if ($null -ne $f) { return $f }
    try { return $cfg.facility } catch { return $null }
}

function Facility-IsEnabled($payloadObj) {
    $f = Get-FacilityConfigFromPayloadOrConfig $payloadObj
    $enabled = $false
    try {
        $v = Get-PropValue $f "enabled" $null
        if ($null -ne $v) { $enabled = [bool]$v }
    } catch {}
    return $enabled
}


function Normalize-FacilityScene([string]$scene) {
    if ([string]::IsNullOrWhiteSpace($scene)) { return "Idle" }
    $s = $scene.Trim()

    switch ($s.ToLowerInvariant()) {
        # Preferred scene names (per Step 5 spec)
        "ready"   { return "Ready" }
        "active"  { return "Active" }
        "warning" { return "Warning" }
        "cleanup" { return "Cleanup" }
        "idle"    { return "Idle" }

        # Back-compat aliases
        "warmup"    { return "Ready" }
        "insession" { return "Active" }
        "session"   { return "Active" }
        "warn5"     { return "Warning" }
        "end"       { return "Cleanup" }
        "closed"    { return "Idle" }
        default     { return "Idle" }
    }
}

function Facility-CheckEmergencyStop {
    if ($Global:EmergencyStopEngaged) {
        throw ("EmergencyStop is engaged" + ($(if ($Global:EmergencyStopReason) { ": $Global:EmergencyStopReason" } else { "" })))
    }
}

function Invoke-LightsScene {
    param([Parameter(Mandatory=$true)][string]$Scene, $payloadObj)
    # Placeholder driver. Later: Shelly/Kasa/Lutron/relays/DMX/etc.
    return @{
        device="lights"
        action="SetLights"
        scene=$Scene
        ok=$true
        simulated=$true
        note="placeholder"
    }
}

function Invoke-ProjectorPower {
    param([Parameter(Mandatory=$true)][bool]$On, $payloadObj)
    # Placeholder driver. Later: RS-232 (BenQ), PJLink, etc.
    return @{
        device="projector"
        action="ProjectorPower"
        on=$On
        ok=$true
        simulated=$true
        note="placeholder"
    }
}

function Invoke-AudioVolume {
    param([Parameter(Mandatory=$true)]$Level, $payloadObj)
    # Placeholder driver. Later options:
    # - Windows system volume via a helper tool (nircmd) or an audio endpoint API wrapper
    # - AV receiver / amp via IP/RS-232
    return @{
        device="audio"
        action="AudioVolume"
        level=$Level
        ok=$true
        simulated=$true
        note="placeholder"
    }
}

function Invoke-EmergencyStopInternal {
    param($payloadObj)

    $reason = $null
    try { $reason = (Get-PropValue $payloadObj "reason" $null) } catch {}
    if ([string]::IsNullOrWhiteSpace([string]$reason)) { $reason = "Emergency stop requested" }

    $Global:EmergencyStopEngaged = $true
    $Global:EmergencyStopReason = $reason

    # Put the bay into a safe scene and show a clear message.
    $facility = Invoke-FacilitySetMode -Mode "Cleanup" -payloadObj $payloadObj

    # Update display model (best-effort)
    try {
        $existing = Read-SessionModelFromDisk
        $ht = To-Hashtable $existing
        $ht.bannerText = "EMERGENCY STOP"
        $ht.statusDetail = $reason
        $ht.status = "STOP"
        $ht = Normalize-SessionModel $ht
        Write-SessionFiles $ht | Out-Null
        Start-SessionDisplay $payloadObj | Out-Null
    } catch {}

    return @{
        ok = $true
        engaged = $true
        reason = $reason
        facility = $facility
    }
}

function Clear-EmergencyStopInternal {
    $Global:EmergencyStopEngaged = $false
    $Global:EmergencyStopReason = $null
    return @{ ok=$true; engaged=$false }
}

function Invoke-FacilitySetMode {
    param(
        [Parameter(Mandatory=$true)][string]$Mode,
        $payloadObj
    )

    # Facility scenes per Step 5 spec:
    #   Ready / Active / Warning / Cleanup / Idle
    #
    # Back-compat:
    #   Warmup -> Ready
    #   InSession -> Active
    #   Closed -> Idle
    $scene = Normalize-FacilityScene $Mode

    # If EmergencyStop is latched, do not allow scene changes (except Cleanup/Idle via Reset/Clear).
    if ($Global:EmergencyStopEngaged -and ($scene -ne "Cleanup") -and ($scene -ne "Idle")) {
        return @{
            ok = $false
            enabled = (Facility-IsEnabled $payloadObj)
            scene = $scene
            emergencyStop = @{ engaged = $true; reason = $Global:EmergencyStopReason }
            note = "emergency_stop_engaged"
        }
    }

    # Build a plan (device/action pairs). Even when facility is disabled, returning the plan helps validate Step 5.
    $actions = @()
    switch ($scene) {
        "Idle" {
            $actions += @{ device="projector"; action=@{ type="ProjectorPower"; on=$false } }
            $actions += @{ device="lights"; action=@{ type="SetLights"; scene="Idle" } }
            $actions += @{ device="audio"; action=@{ type="AudioVolume"; level="mute" } }
        }
        "Ready" {
            $actions += @{ device="projector"; action=@{ type="ProjectorPower"; on=$true } }
            $actions += @{ device="lights"; action=@{ type="SetLights"; scene="Ready" } }
            $actions += @{ device="audio"; action=@{ type="AudioVolume"; level=20 } }
        }
        "Active" {
            $actions += @{ device="projector"; action=@{ type="ProjectorPower"; on=$true } }
            $actions += @{ device="lights"; action=@{ type="SetLights"; scene="Active" } }
            $actions += @{ device="audio"; action=@{ type="AudioVolume"; level=35 } }
        }
        "Warning" {
            $actions += @{ device="lights"; action=@{ type="SetLights"; scene="Warning" } }
            $actions += @{ device="audio"; action=@{ type="AudioVolume"; level=35 } }
        }
        "Cleanup" {
            $actions += @{ device="projector"; action=@{ type="ProjectorPower"; on=$false } }
            $actions += @{ device="lights"; action=@{ type="SetLights"; scene="Cleanup" } }
            $actions += @{ device="audio"; action=@{ type="AudioVolume"; level="mute" } }
        }
        default {
            $actions += @{ device="projector"; action=@{ type="ProjectorPower"; on=$false } }
            $actions += @{ device="lights"; action=@{ type="SetLights"; scene="Idle" } }
            $actions += @{ device="audio"; action=@{ type="AudioVolume"; level="mute" } }
        }
    }

    # Execute the plan via driver stubs. Later we will route each device to real drivers (Shelly/Kasa/Lutron/RS-232/PJLink/etc.).
    $results = @()
    foreach ($a in $actions) {
        $dev = $a.device
        $act = $a.action

        switch ($act.type) {
            "SetLights" {
                $results += Invoke-LightsScene -Scene $act.scene -payloadObj $payloadObj
            }
            "ProjectorPower" {
                $results += Invoke-ProjectorPower -On ([bool]$act.on) -payloadObj $payloadObj
            }
            "AudioVolume" {
                $results += Invoke-AudioVolume -Level $act.level -payloadObj $payloadObj
            }
            default {
                $results += @{
                    device = $dev
                    action = $act.type
                    ok = $true
                    simulated = $true
                    note = "unknown_action_type_placeholder"
                }
            }
        }
    }

    return @{
        ok = $true
        scene = $scene
        enabled = (Facility-IsEnabled $payloadObj)
        simulated = $true
        plan = $actions
        results = $results
    }
}


function Start-SessionDisplay($payloadObj) {
    # Session Display settings can come from the command payload OR agent-config.json.
    # Payload wins, config provides stable defaults so you don't have to modify flows.
    $sdPayload = Get-PropValue $payloadObj "sessionDisplay" $null
    $sdCfg = $null
    try { if ($cfg.PSObject.Properties.Name -contains "sessionDisplay") { $sdCfg = $cfg.sessionDisplay } } catch {}

    $enabled = Get-PropValue $sdPayload "enabled" (Get-PropValue $sdCfg "enabled" $true)
    if ($enabled -eq $false) { return @{ started = $false; reason = "disabled" } }

    $mode = (Get-PropValue $sdPayload "mode" (Get-PropValue $sdCfg "mode" "kiosk")).ToString().ToLowerInvariant()

    $edgePath = Get-PropValue $sdPayload "edgePath" (Get-PropValue $sdCfg "edgePath" $null)
    if ([string]::IsNullOrWhiteSpace([string]$edgePath)) { $edgePath = Get-DefaultEdgePath }

    $url = Get-PropValue $sdPayload "url" (Get-PropValue $sdCfg "url" $null)
    if ([string]::IsNullOrWhiteSpace([string]$url)) { $url = "file:///C:/AllBirdies/SessionDisplay/index.html" }

    $profileDir = Get-PropValue $sdPayload "profileDir" (Get-PropValue $sdCfg "profileDir" $Global:SessionDisplayProfileDir)
    if ([string]::IsNullOrWhiteSpace([string]$profileDir)) { $profileDir = "C:\AllBirdies\SessionDisplay\edge-profile" }

    # Desired display role for signage
    $role = Get-PropValue $sdPayload "displayRole" (Get-PropValue $sdCfg "displayRole" $null)
    if ([string]::IsNullOrWhiteSpace([string]$role)) { $role = "session" }

    # Compute target bounds up-front so we can spawn the window on the correct monitor
    $targetBounds = $null
    try {
        $screen = Get-ScreenForRole $role $payloadObj
        if ($null -ne $screen) { $targetBounds = $screen.Bounds }
    } catch {}

    # Find ALL Edge processes using our dedicated profile dir (browser + renderer processes)
    function Get-EdgePidsForProfile([string]$pdir) {
        $ids = @()
        try {
            $edgeCim = Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" -OperationTimeoutSec 2 -ErrorAction SilentlyContinue
            foreach ($p in $edgeCim) {
                $cmd = $p.CommandLine
                if ($null -ne $cmd -and $cmd -like "*$pdir*") { $ids += [int]$p.ProcessId }
            }
        } catch {}
        return $ids
    }

    function Pick-EdgePidWithWindow([int[]]$pids) {
        foreach ($id in $pids) {
            try {
                $h = Get-FirstVisibleWindowHandleForPid $id
                if ($h -ne [IntPtr]::Zero) { return $id }
            } catch {}
        }
        if ($pids.Count -gt 0) { return $pids[0] }
        return $null
    }

    $existingPids = @(Get-EdgePidsForProfile $profileDir)

    if ($existingPids.Count -gt 0) {
        # IMPORTANT: pick the PID that actually owns the visible window (Edge spawns many processes)
        $pidToUse = Pick-EdgePidWithWindow $existingPids
        if ($null -eq $pidToUse) { $pidToUse = $existingPids[0] }

        $Global:SessionDisplayProcId = $pidToUse
        $Global:SessionDisplayUrl = $url

        # Best-effort route to the Session screen and maximize
        try { $null = Safe-RouteProcessWindow -context "SessionDisplay:already_running" -pid ([int]$pidToUse) -role $role -payloadObj $payloadObj -Maximize } catch {}

        return @{ started = $false; reason = "already_running"; mode = $mode; url = $url; pid = $pidToUse; procId = $pidToUse; profileDir = $profileDir }
    }

    # Tag the Session Display Edge instance with a dedicated profile directory.
    # This makes EndSession/Reset reliable even if other Edge windows are open.
    $args = "--allow-file-access-from-files --user-data-dir=$profileDir --no-first-run --no-default-browser-check "

    # Spawn on the correct monitor (best effort). Works well for multi-monitor layouts.
    if ($null -ne $targetBounds) {
        $args += "--window-position=$($targetBounds.Left),$($targetBounds.Top) --window-size=$($targetBounds.Width),$($targetBounds.Height) "
    }

    if ($mode -eq "kiosk") {
        # Fullscreen signage mode (no borders, no taskbar)
        $args += "--kiosk ""$url"" --edge-kiosk-type=fullscreen --kiosk-idle-timeout-minutes=0"
    } else {
        # App mode (borderless-ish); start fullscreen improves reliability
        $args += "--app=""$url"" --start-fullscreen"
    }

    $proc = Start-Process -FilePath $edgePath -ArgumentList $args -PassThru

    # Edge may spawn multiple processes; route the PID that actually owns the visible window.
    $pidToRoute = $proc.Id
    $deadline = (Get-Date).AddSeconds(10)
    do {
        try {
            $h = Get-FirstVisibleWindowHandleForPid $pidToRoute
            if ($h -ne [IntPtr]::Zero) { break }
        } catch {}

        # Rescan and pick a PID with a window for our profile dir
        $pids = @(Get-EdgePidsForProfile $profileDir)
        $pick = Pick-EdgePidWithWindow $pids
        if ($null -ne $pick) { $pidToRoute = $pick; break }

        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)

    $Global:SessionDisplayProcId = $pidToRoute
    $Global:SessionDisplayUrl = $url

    # Persist a tiny bit of state so EndSession works even if the agent is restarted
    try {
        $state = @{
            pid        = $pidToRoute
            procId     = $pidToRoute
            url        = $url
            profileDir = $profileDir
            startedUtc = (Get-Date).ToUniversalTime().ToString("o")
        }
        Write-JsonAtomic -path $Global:SessionDisplayStatePath -obj $state
    } catch { }

    # Route to Session screen and maximize (best effort)
    try { $null = Safe-RouteProcessWindow -context "SessionDisplay:started" -pid ([int]$pidToRoute) -role $role -payloadObj $payloadObj -Maximize } catch {}

    return @{ started = $true; mode = $mode; edgePath = $edgePath; url = $url; pid = $pidToRoute; procId = $pidToRoute; profileDir = $profileDir }
}



function Start-GenericProcess($payloadObj) {
    if ($null -eq $payloadObj) { throw "StartProcess payload must be valid JSON." }

    $path = Get-PropValue $payloadObj "path" $null
    $args = Get-PropValue $payloadObj "args" $null

    # Step 7 hardening: prevent StartProcess from bypassing execution policy or running inline PowerShell.
    # (All scripts must run under LocalMachine=AllSigned; do NOT allow -ExecutionPolicy Bypass / -EncodedCommand.)
    $argsText = [string]$args
    if (-not [string]::IsNullOrWhiteSpace($argsText)) {
        $al = $argsText.ToLowerInvariant()

        $badTokens = @(
            "-executionpolicy bypass",
            "-ep bypass",
            "-executionpolicy unrestricted",
            "-encodedcommand",
            "-enc "
        )

        foreach ($t in $badTokens) {
            if ($al.Contains($t)) {
                throw "StartProcess args contains disallowed token '$t'. Remove it and rely on AllSigned."
            }
        }

        # If launching PowerShell, require -File <script> under C:\AllBirdies\BayAgent and block -Command.
        $leaf = ([IO.Path]::GetFileName([string]$path)).ToLowerInvariant()
        if ($leaf -in @("powershell.exe","pwsh.exe")) {
            if ($al -match "\s-(command|c)\s+") { throw "StartProcess launching PowerShell cannot use -Command/-c. Use -File <script>." }

            $m = [regex]::Match($argsText, '(?i)\s-file\s+("([^"]+)"|(\S+))')
            if (-not $m.Success) { throw "StartProcess launching PowerShell must use -File <script> (no inline commands)." }

            $scriptPath = $m.Groups[2].Value
            if ([string]::IsNullOrWhiteSpace($scriptPath)) { $scriptPath = $m.Groups[3].Value }
            $scriptPath = $scriptPath.Trim()

            if ([string]::IsNullOrWhiteSpace($scriptPath)) { throw "StartProcess PowerShell args must include a script path after -File." }

            $allowedBase = $BaseDir
            if (-not ($scriptPath.ToLowerInvariant().StartsWith($allowedBase.ToLowerInvariant()))) {
                throw "StartProcess PowerShell scripts must be under $allowedBase. Got: $scriptPath"
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace([string]$path)) { throw "StartProcess requires payload.path" }

    if (!(Test-Path $path)) { throw "Executable not found: $path" }

    if ([string]::IsNullOrWhiteSpace([string]$args)) {
        $p = Start-Process -FilePath $path -PassThru
    } else {
        $p = Start-Process -FilePath $path -ArgumentList $args -PassThru
    }

    return @{
        started = $true
        path = $path
        args = $args
        pid = $p.Id
    }
}

function Stop-GenericProcess($payloadObj) {
    if ($null -eq $payloadObj) { throw "StopProcess payload must be valid JSON." }

    $force = [bool](Get-PropValue $payloadObj "force" $false)

    $procId = Get-PropValue $payloadObj "pid" $null
    if ($null -eq $procId) { $procId = Get-PropValue $payloadObj "procId" $null }

    if ($null -ne $procId) {
        Stop-Process -Id ([int]$procId) -Force:$force -ErrorAction Stop
        return @{ stopped = $true; mode = "pid"; pid = [int]$procId; force = $force }
    }

    $processName = Get-PropValue $payloadObj "processName" $null
    if (-not [string]::IsNullOrWhiteSpace([string]$processName)) {
        $base = [System.IO.Path]::GetFileNameWithoutExtension([string]$processName)
        $procs = Get-Process -Name $base -ErrorAction SilentlyContinue
        if (-not $procs) { return @{ stopped = $false; mode = "name"; processName = $processName; reason = "not_running" } }
        $ids = @($procs | Select-Object -ExpandProperty Id)
        $procs | Stop-Process -Force:$force -ErrorAction Stop
        return @{ stopped = $true; mode = "name"; processName = $processName; pids = $ids; force = $force }
    }

    throw "StopProcess requires payload.pid (or procId) or payload.processName"
}

function Query-GenericProcess($payloadObj) {
    if ($null -eq $payloadObj) { throw "QueryProcess payload must be valid JSON." }

    $procId = Get-PropValue $payloadObj "pid" $null
    if ($null -eq $procId) { $procId = Get-PropValue $payloadObj "procId" $null }

    if ($null -ne $procId) {
        $p = Get-Process -Id ([int]$procId) -ErrorAction SilentlyContinue
        return @{ mode = "pid"; pid = [int]$procId; running = ($null -ne $p) }
    }

    $processName = Get-PropValue $payloadObj "processName" $null
    if (-not [string]::IsNullOrWhiteSpace([string]$processName)) {
        $base = [System.IO.Path]::GetFileNameWithoutExtension([string]$processName)
        $procs = Get-Process -Name $base -ErrorAction SilentlyContinue
        return @{ mode = "name"; processName = $processName; running = [bool]$procs; count = ($procs | Measure-Object).Count; pids = @($procs | Select-Object -ExpandProperty Id) }
    }

    throw "QueryProcess requires payload.pid (or procId) or payload.processName"
}


function Stop-SessionDisplay {
    # Close the visible Session Display window reliably.
    # We strongly prefer killing Edge processes that are using our dedicated profile directory.
    $url = $Global:SessionDisplayUrl
    $profileDir = $Global:SessionDisplayProfileDir
    $rootPid = $Global:SessionDisplayProcId

    # Recover state if needed (e.g., agent restarted)
    try {
        if (Test-Path $Global:SessionDisplayStatePath) {
            $st = (Get-Content $Global:SessionDisplayStatePath -Raw -Encoding UTF8) | ConvertFrom-Json
            if ([string]::IsNullOrWhiteSpace([string]$url)) { $url = Get-PropValue $st "url" $url }
            if ([string]::IsNullOrWhiteSpace([string]$profileDir)) { $profileDir = Get-PropValue $st "profileDir" $profileDir }
            if ($null -eq $rootPid) { $rootPid = Get-PropValue $st "procId" $rootPid }
            if ($null -eq $rootPid) { $rootPid = Get-PropValue $st "pid" $rootPid }
        }
    } catch { }

    if ([string]::IsNullOrWhiteSpace([string]$url)) { $url = "file:///C:/AllBirdies/SessionDisplay/index.html" }
    if ([string]::IsNullOrWhiteSpace([string]$profileDir)) { $profileDir = "C:\AllBirdies\SessionDisplay\edge-profile" }

    $pids = New-Object System.Collections.Generic.HashSet[int]

    function Add-Pid([int]$procId) {
        if ($procId -gt 0) { [void]$pids.Add($procId) }
    }

    function Add-Children([int[]]$parents) {
        foreach ($pp in $parents) {
            try {
                $kids = Get-CimInstance Win32_Process -Filter "ParentProcessId=$pp" -OperationTimeoutSec 2 -ErrorAction SilentlyContinue |
                        Select-Object -ExpandProperty ProcessId
                foreach ($k in $kids) { Add-Pid ([int]$k) }
            } catch { }
        }
    }

    # 1) Strongest match: Edge processes that include our profile directory in the command line.
    try {
        $edgeCim = Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" -OperationTimeoutSec 2 -ErrorAction SilentlyContinue
        foreach ($p in $edgeCim) {
            $cmd = $p.CommandLine
            if ($null -ne $cmd -and $cmd -like "*$profileDir*") {
                Add-Pid ([int]$p.ProcessId)
            }
        }
    } catch { }

    # Add children of those matches (helps close the actual window)
    try { Add-Children @($pids) } catch { }

    # 2) Window-title match (fallback)
    try {
        $edge = Get-Process -Name msedge -ErrorAction SilentlyContinue
        foreach ($p in $edge) {
            $t = $p.MainWindowTitle
            if (-not [string]::IsNullOrWhiteSpace($t) -and $t -like "*ABG Session Display*") {
                Add-Pid ([int]$p.Id)
            }
        }
    } catch { }

    # 3) URL match (last resort)
    try {
        $edgeCim2 = Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" -OperationTimeoutSec 2 -ErrorAction SilentlyContinue
        foreach ($p in $edgeCim2) {
            $cmd = $p.CommandLine
            if ($null -ne $cmd -and $cmd -like "*$url*") {
                Add-Pid ([int]$p.ProcessId)
            }
        }
    } catch { }

    # 4) Fallback: root pid (if we have it)
    if ($null -ne $rootPid) { Add-Pid ([int]$rootPid) }

    $killList = @($pids | Sort-Object -Descending)
    if ($killList.Count -eq 0) {
        return @{ stopped = $false; reason = "not_found"; url = $url; profileDir = $profileDir }
    }

    foreach ($id in $killList) {
        try { Stop-Process -Id $id -Force -ErrorAction SilentlyContinue } catch { }
    }

    # Clear state
    $Global:SessionDisplayProcId = $null

# Emergency stop latch (cleared only by explicit command)
$Global:EmergencyStopEngaged = $false
$Global:EmergencyStopReason = $null
    $Global:SessionDisplayUrl = $null
    try { if (Test-Path $Global:SessionDisplayStatePath) { Remove-Item $Global:SessionDisplayStatePath -Force -ErrorAction SilentlyContinue } } catch { }

    return @{ stopped = $true; url = $url; profileDir = $profileDir; killedPids = $killList }
}

function Execute-Command {
    param(
        [Parameter(Mandatory=$true)][int]$CommandType,
        [string]$PayloadJson,
        [string]$BayLabel
    )
    $payloadObj = Try-ParseJson $PayloadJson


# Inject bay label into payload so Session Display can show it dynamically across multiple bays.
$effectiveBayLabel = $BayLabel
if ([string]::IsNullOrWhiteSpace([string]$effectiveBayLabel)) { $effectiveBayLabel = (Get-BayLabel) }

if ($null -ne $payloadObj) {
    Set-PropValue -obj $payloadObj -name "bayLabel" -value $effectiveBayLabel -OnlyIfMissing
    Set-PropValue -obj $payloadObj -name "locationLabel" -value $effectiveBayLabel -OnlyIfMissing
    Set-PropValue -obj $payloadObj -name "bayId" -value $BayId -OnlyIfMissing
}
    switch ($CommandType) {
        $CMD_HEALTHCHECK {
            $nowHb = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            return @{
                ok = $true
                agentVersion = $AgentVersion
                machine = $env:COMPUTERNAME
                bayId = $BayId
                utc = $nowHb
            }
        }

        
$CMD_DISPLAY_TOPOLOGY {
    return @{
        ok = $true
        topology = @((Get-DisplayTopology))
    }
}

$CMD_FACILITY_SETMODE {
    if ($null -eq $payloadObj) { $payloadObj = @{} }
    $mode = (Get-PropValue $payloadObj "mode" "Idle").ToString()

    $res = Invoke-FacilitySetMode -Mode $mode -payloadObj $payloadObj
    $res.requestedMode = $mode
    if (-not (Facility-IsEnabled $payloadObj)) {
        $res.note = "facility.disabled"
        $res.topology = @((Get-DisplayTopology))
    }
    return $res
}

$CMD_FACILITY_POWERON {
    if ($null -eq $payloadObj) { $payloadObj = @{} }
    if (-not (Facility-IsEnabled $payloadObj)) {
        return @{ ok = $true; enabled = $false; note = "facility.disabled"; requestedMode = "Ready" }
    }
    return (Invoke-FacilitySetMode -Mode "Ready" -payloadObj $payloadObj)
}

$CMD_FACILITY_POWEROFF {
    if ($null -eq $payloadObj) { $payloadObj = @{} }
    if (-not (Facility-IsEnabled $payloadObj)) {
        return @{ ok = $true; enabled = $false; note = "facility.disabled"; requestedMode = "Idle" }
    }
    return (Invoke-FacilitySetMode -Mode "Idle" -payloadObj $payloadObj)
}


$CMD_SETLIGHTS {
    if ($null -eq $payloadObj) { $payloadObj = @{} }
    if ($Global:EmergencyStopEngaged) {
        return @{ ok=$false; note="emergency_stop_engaged"; emergencyStop=@{ engaged=$true; reason=$Global:EmergencyStopReason } }
    }
    $scene = (Get-PropValue $payloadObj "scene" "Idle").ToString()
    return @{
        ok = $true
        result = (Invoke-LightsScene -Scene (Normalize-FacilityScene $scene) -payloadObj $payloadObj)
    }
}

$CMD_PROJECTOR_POWER {
    if ($null -eq $payloadObj) { $payloadObj = @{} }
    if ($Global:EmergencyStopEngaged) {
        return @{ ok=$false; note="emergency_stop_engaged"; emergencyStop=@{ engaged=$true; reason=$Global:EmergencyStopReason } }
    }
    $onVal = Get-PropValue $payloadObj "on" $false
    $on = [bool]$onVal
    return @{
        ok = $true
        result = (Invoke-ProjectorPower -On $on -payloadObj $payloadObj)
    }
}

$CMD_AUDIO_VOLUME {
    if ($null -eq $payloadObj) { $payloadObj = @{} }
    if ($Global:EmergencyStopEngaged) {
        return @{ ok=$false; note="emergency_stop_engaged"; emergencyStop=@{ engaged=$true; reason=$Global:EmergencyStopReason } }
    }
    $level = Get-PropValue $payloadObj "level" 30
    return @{
        ok = $true
        result = (Invoke-AudioVolume -Level $level -payloadObj $payloadObj)
    }
}

$CMD_EMERGENCY_STOP {
    if ($null -eq $payloadObj) { $payloadObj = @{} }
    $action = (Get-PropValue $payloadObj "action" "engage").ToString()
    if ($action.ToLowerInvariant() -eq "clear") {
        return (Clear-EmergencyStopInternal)
    }
    return (Invoke-EmergencyStopInternal -payloadObj $payloadObj)
}


        $CMD_SHOWMESSAGE {
            $title = Get-PropValue $payloadObj "title" "All Birdies"
            $message = Get-PropValue $payloadObj "message" "Hello from Bay Agent"
            $timeoutSec = [int](Get-PropValue $payloadObj "timeoutSec" 8)

            try {
                $ws = New-Object -ComObject WScript.Shell
                $code = $ws.Popup([string]$message, $timeoutSec, [string]$title, 0)
                return @{ shown = $true; timeoutSec = $timeoutSec; resultCode = $code }
            } catch {
                return @{ shown = $false; error = $_.Exception.Message }
            }
        }
        $CMD_STARTPROCESS {
            return (Start-GenericProcess $payloadObj)
        }

        $CMD_STOPPROCESS {
            return (Stop-GenericProcess $payloadObj)
        }

        $CMD_QUERYPROCESS {
            return (Query-GenericProcess $payloadObj)
        }



        $CMD_UPDATESESSIONDISPLAY {
            if ($null -eq $payloadObj) { throw "UpdateSessionDisplay payload must be valid JSON." }

            # Merge with last known model so partial updates (like Warn5) don't wipe start/end/name.
            $existing = Read-SessionModelFromDisk
            $baseHt = To-Hashtable $existing
            $payloadHt = To-Hashtable $payloadObj
            $patch = Build-SessionDisplayPatchFromPayload $payloadObj

            $tmp = Merge-Hashtables $baseHt $payloadHt
            $model = Merge-Hashtables $tmp $patch

            # Ensure a few safe defaults
            if ([string]::IsNullOrWhiteSpace([string](Get-PropValue $model "locationLabel" $null))) { $model.locationLabel = $effectiveBayLabel }
            if ([string]::IsNullOrWhiteSpace([string](Get-PropValue $model "displayName" $null))) { $model.displayName = "Guest" }
            if ([string]::IsNullOrWhiteSpace([string](Get-PropValue $model "helpText" $null))) { $model.helpText = (Get-HelpText) }

            $model = Normalize-SessionModel $model
            $paths = Write-SessionFiles $model

            # Make sure the display is up (no duplicates).
            $display = Start-SessionDisplay $payloadObj

            $facility = $null
            try {
                $mode2 = Get-PropValue $payloadObj "mode" $null
                $scene2 = Get-PropValue $payloadObj "scene" $null
                if (-not [string]::IsNullOrWhiteSpace([string]$scene2)) {
                    $facility = Invoke-FacilitySetMode -Mode $scene2 -payloadObj $payloadObj
                } elseif (-not [string]::IsNullOrWhiteSpace([string]$mode2) -and $mode2.ToString().ToLowerInvariant() -eq "warn5") {
                    $facility = Invoke-FacilitySetMode -Mode "Warning" -payloadObj $payloadObj
                }
            } catch {
                $facility = @{ ok = $false; error = $_.Exception.Message }
            }

            return @{
                updated = $true
                sessionJsonPath = $paths.sessionJsonPath
                sessionJsPath = $paths.sessionJsPath
                display = $display
                facility = $facility
            }
        }

        $CMD_STARTSESSION {
            if ($null -eq $payloadObj) { throw "StartSession payload must be valid JSON." }

            $existing = Read-SessionModelFromDisk
            $baseHt = To-Hashtable $existing
            $payloadHt = To-Hashtable $payloadObj

            # Session boundary rules:
            # - Prep should NOT launch Uneekor Launcher (prevents early play)
            # - Start SHOULD launch Uneekor Launcher
            $mode = (Get-PropValue $payloadObj "mode" "").ToString()
            $modeLower = $mode.ToLowerInvariant()

            # Facility scene tied to the session (Step 5).
            $facility = $null

            # If EmergencyStop is latched, block session starts and force a safe scene.
            if ($Global:EmergencyStopEngaged) {
                try {
                    $facility = Invoke-FacilitySetMode -Mode "Cleanup" -payloadObj $payloadObj
                } catch {
                    $facility = @{ ok = $false; error = $_.Exception.Message }
                }

                return @{
                    ok = $false
                    note = "emergency_stop_engaged"
                    emergencyStop = @{ engaged = $true; reason = $Global:EmergencyStopReason }
                    facility = $facility
                }
            }

            # Otherwise, apply the appropriate facility scene for the session phase.
            try {
                $scene = if ($modeLower -eq "start") { "Active" } elseif ($modeLower -eq "prep") { "Ready" } else { "Idle" }
                $facility = Invoke-FacilitySetMode -Mode $scene -payloadObj $payloadObj
            } catch {
                $facility = @{ ok = $false; error = $_.Exception.Message }
            }

            # Prevent stale/previous-session statusDetail (e.g., "Thanks for choosing All Birdies.") from carrying into Prep/Start
            if ($modeLower -eq "prep") {
                $payloadHt.status = "PREP"
                $payloadHt.statusDetail = ""   # allow display.js to show "Starts in"
                $payloadHt.bannerText = ""
            } elseif ($modeLower -eq "start") {
                $payloadHt.status = "ACTIVE"
                if ([string]::IsNullOrWhiteSpace([string](Get-PropValue $payloadHt "statusDetail" $null)) -and
                    [string]::IsNullOrWhiteSpace([string](Get-PropValue $payloadHt "bannerText" $null))) {
                    $payloadHt.statusDetail = "In progress."
                }
                $payloadHt.bannerText = ""
            }

            $patch = Build-SessionDisplayPatchFromPayload $payloadHt

            $tmp = Merge-Hashtables $baseHt $payloadHt
            $model = Merge-Hashtables $tmp $patch

            if ([string]::IsNullOrWhiteSpace([string](Get-PropValue $model "locationLabel" $null))) { $model.locationLabel = $effectiveBayLabel }
            if ([string]::IsNullOrWhiteSpace([string](Get-PropValue $model "displayName" $null))) { $model.displayName = "Guest" }
            if ([string]::IsNullOrWhiteSpace([string](Get-PropValue $model "helpText" $null))) { $model.helpText = (Get-HelpText) }

            $model = Normalize-SessionModel $model
            $paths = Write-SessionFiles $model

            # Ensure the Session Display is running (no duplicates).
            $display = Start-SessionDisplay $payloadObj

            # Launcher should start ONLY at "Start"
            $launcherCfg = Get-LauncherConfigFromPayloadOrConfig $payloadObj
            if ([string]::IsNullOrWhiteSpace([string]$launcherCfg.path)) { $launcherCfg.path = "C:\Uneekor\Launcher\UneekorLauncher.exe" }

            $launcher = $null
            if ($modeLower -eq "start") {
                $startOnStart = $launcherCfg.startOnStart
                if ($null -eq $startOnStart) { $startOnStart = $true }
                if ([bool]$startOnStart) {
                    $launcher = Start-LauncherIfNeeded "StartSession:Start" $launcherCfg
                } else {
                    $launcher = @{ started = $false; reason = "startOnStart_false" }
                }
            } else {
                $launcher = @{ started = $false; reason = "prep_or_unknown_mode" }
            }

            return @{
                ok = $true
                mode = $mode
                sessionJsonPath = $paths.sessionJsonPath
                sessionJsPath = $paths.sessionJsPath
                display = $display
                launcher = $launcher
                facility = $facility
            }
        }


        $CMD_ENDSESSION {
            # End of session:
            #  - Close Uneekor Launcher by default (prevents overtime)
            #  - Keep Session Display open by default and show a thank-you message
            if ($null -eq $payloadObj) { $payloadObj = @{} }

            # Facility: EndSession always moves the bay to the Cleanup scene (Step 5).
            $facility = $null
            try {
                $facility = Invoke-FacilitySetMode -Mode "Cleanup" -payloadObj $payloadObj
            } catch {
                $facility = @{ ok = $false; error = $_.Exception.Message }
            }

            function Get-ProcessesByExePathOrName([string]$exePath) {
                $list = @()
                if ([string]::IsNullOrWhiteSpace($exePath)) { return @() }

                $exeLeaf = [System.IO.Path]::GetFileName($exePath)
                $baseName = [System.IO.Path]::GetFileNameWithoutExtension($exePath)

                # 1) Try Get-Process Path match (may fail for some processes due to permissions)
                try {
                    $list += @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path -ieq $exePath })
                } catch {}

                # 2) Try CIM ExecutablePath match (more reliable on some systems)
                if (-not $list -or @($list).Count -eq 0) {
                    try {
                        $cim = @(Get-CimInstance Win32_Process -Filter "Name='$exeLeaf'" -ErrorAction SilentlyContinue)
                        foreach ($c in $cim) {
                            try {
                                if ($c.ExecutablePath -and $c.ExecutablePath -ieq $exePath) {
                                    $p = Get-Process -Id $c.ProcessId -ErrorAction SilentlyContinue
                                    if ($p) { $list += $p }
                                }
                            } catch {}
                        }
                    } catch {}
                }

                # 3) Directory scan fallback (handles cases where Process.Path is unavailable or exe name differs)
                if (-not $list -or @($list).Count -eq 0) {
                    try {
                        $dir = [System.IO.Path]::GetDirectoryName($exePath)
                        if (-not [string]::IsNullOrWhiteSpace($dir)) {
                            $cimAll = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
                                $_.ExecutablePath -and ($_.ExecutablePath -like ($dir + "\*"))
                            })
                            foreach ($c in $cimAll) {
                                try {
                                    $p = Get-Process -Id $c.ProcessId -ErrorAction SilentlyContinue
                                    if ($p) { $list += $p }
                                } catch {}
                            }
                        }
                    } catch {}
                }

                # 4) Fallback to process name (last resort)
                if (-not $list -or @($list).Count -eq 0) {
                    try { $list += @(Get-Process -Name $baseName -ErrorAction SilentlyContinue) } catch {}
                }

                return @($list | Sort-Object Id -Unique)
            }

            function Stop-ProcessesGracefully([object[]]$procs, [int]$waitSec = 8) {
                $procs = @($procs)
                if (-not $procs -or $procs.Count -eq 0) { return @{ stopped = $false; reason = "not_running" } }

                foreach ($p in $procs) {
                    try {
                        if ($p.MainWindowHandle -ne 0) { $null = $p.CloseMainWindow() }
                    } catch {}
                }

                $deadline = (Get-Date).AddSeconds($waitSec)
                do {
                    Start-Sleep -Milliseconds 250
                    $still = @()
                    foreach ($p in $procs) {
                        try {
                            $cur = Get-Process -Id $p.Id -ErrorAction SilentlyContinue
                            if ($cur) { $still += $cur }
                        } catch {}
                    }
                } while ($still.Count -gt 0 -and (Get-Date) -lt $deadline)

                if ($still.Count -gt 0) {
                    foreach ($p in $still) {
                        try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {}
                    }
                    return @{ stopped = $true; method = "kill_after_timeout"; waitSec = $waitSec; count = $still.Count }
                }

                return @{ stopped = $true; method = "closemainwindow"; waitSec = $waitSec; count = $procs.Count }
            }

            $existing = Read-SessionModelFromDisk
            $baseHt = To-Hashtable $existing
            $payloadHt = To-Hashtable $payloadObj

            # Force End mode unless caller already set a specific status/mode.
            if ([string]::IsNullOrWhiteSpace([string](Get-PropValue $payloadHt "mode" $null)) -and
                [string]::IsNullOrWhiteSpace([string](Get-PropValue $payloadObj "status" $null))) {
                $payloadHt.mode = "End"
            }

            # Ensure explicit ENDED status
            if ([string]::IsNullOrWhiteSpace([string](Get-PropValue $payloadHt "status" $null))) { $payloadHt.status = "ENDED" }

            # Default thank-you message unless caller provided one.
            if ([string]::IsNullOrWhiteSpace([string](Get-PropValue $payloadHt "statusDetail" $null)) -and
                [string]::IsNullOrWhiteSpace([string](Get-PropValue $payloadHt "bannerText" $null))) {
                $payloadHt.statusDetail = "Thanks for choosing All Birdies."
            }

            $patch = Build-SessionDisplayPatchFromPayload $payloadHt
            $tmp = Merge-Hashtables $baseHt $payloadHt
            $model = Merge-Hashtables $tmp $patch

            if ([string]::IsNullOrWhiteSpace([string](Get-PropValue $model "locationLabel" $null))) { $model.locationLabel = $effectiveBayLabel }
            if ([string]::IsNullOrWhiteSpace([string](Get-PropValue $model "displayName" $null))) { $model.displayName = "Guest" }
            if ([string]::IsNullOrWhiteSpace([string](Get-PropValue $model "helpText" $null))) { $model.helpText = (Get-HelpText) }

            $model = Normalize-SessionModel $model
            $paths = Write-SessionFiles $model

            $apps = Stop-AppsIfRequested $payloadObj

            # Guard against late/out-of-order EndSession for an older session (e.g., back-to-back bookings).
            $payloadSessionId = [string](Get-PropValue $payloadObj "baySessionId" "")
            $currentSessionId = [string](Get-PropValue $existing "baySessionId" "")
            $sameSession = $true
            if (-not [string]::IsNullOrWhiteSpace($payloadSessionId) -and -not [string]::IsNullOrWhiteSpace($currentSessionId) -and ($payloadSessionId -ne $currentSessionId)) {
                $sameSession = $false
            }

            # Close the Uneekor Launcher by default (prevents playing past end time).
            $launcherCfg = Get-LauncherConfigFromPayloadOrConfig $payloadObj
            if ([string]::IsNullOrWhiteSpace([string]$launcherCfg.path)) { $launcherCfg.path = "C:\Uneekor\Launcher\UneekorLauncher.exe" }

            $closeLauncher = [bool](Get-PropValue $payloadObj "closeLauncher" $true)
            if (-not $sameSession) { $closeLauncher = $false }

            $launcherStopped = $null
            if ($closeLauncher) {
                $procs = Get-ProcessesByExePathOrName $launcherCfg.path
                $launcherStopped = Stop-ProcessesGracefully $procs 8
                if (-not $launcherStopped.stopped -and $launcherStopped.reason -eq "not_running") {
                    $launcherStopped = @{ stopped = $false; reason = "not_running"; path = $launcherCfg.path; found = 0 }
                }
            } else {
                if ($sameSession) {
                $launcherStopped = @{ stopped = $false; reason = "closeLauncher_false" }
            } else {
                $launcherStopped = @{ stopped = $false; reason = "late_old_session_skip" }
            }
            }

            # Keep Session Display open by default, showing the thank-you state.
            $closeDisplay = [bool](Get-PropValue $payloadObj "closeDisplay" $false)
            $display = $null
            $displayStopped = $null
            if ($closeDisplay) {
                $displayStopped = Stop-SessionDisplay
            } else {
                $display = Start-SessionDisplay $payloadObj
            }

            return @{
                ok = $true
                sessionJsonPath = $paths.sessionJsonPath
                sessionJsPath = $paths.sessionJsPath
                facility = $facility
                apps = $apps
                launcherStopped = $launcherStopped
                closeDisplay = $closeDisplay
                display = $display
                displayStopped = $displayStopped
            }
        }

        $CMD_RESET {
            # Reset to a known-good "READY" state.
            # Default behavior: keep the Session Display running (or restart it) so the bay never sits on a blank screen.
            if ($null -eq $payloadObj) { $payloadObj = @{} }

            $closeDisplay   = [bool](Get-PropValue $payloadObj "closeDisplay" $false)
            $restartDisplay = [bool](Get-PropValue $payloadObj "restartDisplay" $true)

            $stop = $null
            if ($closeDisplay -or $restartDisplay) {
                $stop = Stop-SessionDisplay
            }

            $now = (Get-Date).ToUniversalTime().ToString("o")
            $default = @{
                locationLabel = $effectiveBayLabel
                displayName = "Guest"
                status = "READY"
                sessionStartUtc = $now
                sessionEndUtc = $now
                qrUrl = ""
                helpText = "Scan the QR code for help."
            }

            $paths = Write-SessionFiles $default

            $display = $null
            if (-not $closeDisplay) {
                # Ensure the display is up again (no duplicates).
                $display = Start-SessionDisplay $payloadObj
            }

            $facility = $null
            try {
                $facility = Invoke-FacilitySetMode -Mode "Idle" -payloadObj $payloadObj
            } catch {
                $facility = @{ ok = $false; error = $_.Exception.Message }
            }

            return @{
                reset = $true
                closeDisplay = $closeDisplay
                restartDisplay = $restartDisplay
                stopped = $stop
                display = $display
                sessionJsonPath = $paths.sessionJsonPath
                sessionJsPath = $paths.sessionJsPath
                facility = $facility
            }
        }


        default {
            throw "Unknown command type: $CommandType"
        }
    }
}

function Process-Command {
    param(
        [Parameter(Mandatory=$true)][string]$token,
        [Parameter(Mandatory=$true)]$cmd
    )

    $cmdId   = ($cmd.$Col_CommandId.ToString()).Trim("{}")
    $etag    = $cmd.'@odata.etag'
    $type    = [int]$cmd.$Col_CommandType
    $attempt = 0
    try { $attempt = [int]($cmd.$Col_AttemptCount) } catch {}

    if ([string]::IsNullOrWhiteSpace($etag)) {
        Write-Log "Command $cmdId missing @odata.etag; cannot lock safely. Skipping." "ERROR"
        return
    }

    Write-Log "Processing command $cmdId (type=$type attempt=$attempt)" "INFO"

    # 1) LOCK (Pending -> InProgress) using ETag
    $now1 = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    try {
        Patch-Row $token $BayCommandEntitySet $cmdId @{
            $Col_Status       = $STATUS_INPROGRESS
            $Col_StartedOn    = $now1
            $Col_AttemptCount = ($attempt + 1)
        } $etag
    }
    catch {
        Write-Log "Failed to lock command $cmdId (likely already taken). Skipping." "WARN"
        return
    }


# Step 8.3: enforce bay mode (Offline / Maintenance)
$effNow = $(if ($Global:EffectiveConfig) { $Global:EffectiveConfig } else { @{} })
$op = Get-AgentOperationalState -eff $effNow
if ($op.Blocked -and -not (Is-CommandAllowedInMode -CommandType $type -OpState $op)) {
    $nowBlock = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $msg = $op.BlockReason
    try {
        Patch-Row $token $BayCommandEntitySet $cmdId @{
            $Col_Status      = $STATUS_FAILED
            $Col_CompletedOn = $nowBlock
            $Col_Error       = $msg
        } "*"
    } catch {
        Write-Log "Secondary failure: could not mark blocked command $cmdId Failed." "ERROR"
    }
    Write-Log "Command $cmdId blocked: $msg" "WARN"
    return
}

    # 2) EXECUTE + REPORT
    try {
        $payload = $null
        try { $payload = $cmd.$Col_Payload } catch {}

        
$bayLabelFromCmd = Get-BayLabelFromCommandRow $cmd
$resultObj = Execute-Command -CommandType $type -PayloadJson $payload -BayLabel $bayLabelFromCmd
        # Dataverse text columns (e.g., build_resultjson) require a STRING.
        # The baseline Step 1 agent returned JSON strings; we preserve that behavior here.
        $resultJson = $null
        if ($resultObj -is [string]) {
            $resultJson = $resultObj
        } else {
            $resultJson = ($resultObj | ConvertTo-Json -Depth 10 -Compress)
        }

        $now2 = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        Patch-Row $token $BayCommandEntitySet $cmdId @{
            $Col_Status      = $STATUS_SUCCEEDED
            $Col_CompletedOn = $now2
            $Col_Result      = $resultJson
        } "*"

        Write-Log "Command $cmdId succeeded." "INFO"

        # Booking status write-back (non-fatal): update booking when session starts or ends.
        try {
            $payloadForBooking = $null
            try { $payloadForBooking = Try-ParseJson $payload } catch {}
            $bkId = if ($payloadForBooking) { Get-PropValue $payloadForBooking "bookingId" $null } else { $null }
            if (-not [string]::IsNullOrWhiteSpace([string]$bkId)) {
                $bkStatusCode = $null
                if ($type -eq $CMD_STARTSESSION) {
                    $bkMode = if ($payloadForBooking) { (Get-PropValue $payloadForBooking "mode" "").ToString().ToLowerInvariant() } else { "" }
                    if ($bkMode -eq "start") { $bkStatusCode = 271980001 }  # In-process
                }
                elseif ($type -eq $CMD_ENDSESSION) {
                    $bkStatusCode = 271980002  # Complete
                }
                if ($null -ne $bkStatusCode) {
                    Patch-Row $token "build_bookings" $bkId @{ statuscode = $bkStatusCode } "*"
                    Write-Log "Booking $bkId status updated to $bkStatusCode" "INFO"
                }
            }
        } catch {
            Write-Log "Booking status write-back failed (non-fatal): $($_.Exception.Message)" "WARN"
        }
    }
    catch {
        $nowErr = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        $msg = $_.Exception.Message

        try {
            Patch-Row $token $BayCommandEntitySet $cmdId @{
                $Col_Status      = $STATUS_FAILED
                $Col_CompletedOn = $nowErr
                $Col_Error       = $msg
            } "*"
        } catch {
            Write-Log "Secondary failure: could not mark command $cmdId Failed." "ERROR"
        }

        Write-Log "Command $cmdId failed: $msg" "ERROR"
    }
}

# ---------------- Main Loop ----------------
$didWhoAmI = $false

while ($true) {
    try {
        $token = Get-AccessToken

        if ($TokenOnly) {
            Write-Log "TokenOnly mode: token acquired. Exiting." "INFO"
            break
        }

        if (-not $didWhoAmI) {
            Dataverse-WhoAmI $token
            $didWhoAmI = $true
            $Global:NextHeartbeatUtc = [DateTime]::MinValue
        }

        # Step 8.2: refresh effective config (BayProfile + ConfigItems overlay)
        Refresh-EffectiveConfigIfDue $token

        # Step 8.3: if a temporary Offline/Maintenance window has expired, auto-clear back to Online
        AutoClear-ExpiredAgentStatusIfDue $token

        # Update heartbeat on a timer, even if there are no commands
        Send-HeartbeatIfDue $token

        $cmd = Get-NextPendingCommand $token
        if ($cmd) {
            Process-Command $token $cmd
        } else {
            Write-Log "No pending commands." "DEBUG"
        }
    }
    catch {
        Write-Log "Top-level exception: $($_.Exception.Message)" "ERROR"
    }

    if ($Once) { break }

    $jitterMs = Get-Random -Minimum 0 -Maximum 300
    Start-Sleep -Milliseconds $jitterMs
    Start-Sleep -Seconds $PollSec
}

# SIG # Begin signature block
# MIIFiwYJKoZIhvcNAQcCoIIFfDCCBXgCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUu9UtF9gRDCE4mtdEFIDwm5uP
# WdCgggMcMIIDGDCCAgCgAwIBAgIQcB7+YhwgR7ZJib3KL4WIcjANBgkqhkiG9w0B
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
# BAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQU++M39mvNnxEN4VE6kxP/R7ToeVUwDQYJ
# KoZIhvcNAQEBBQAEggEAm6DE7qJpN+i2DIK8xhnqg7E/XikdqFzhIiyI3QRSLy0N
# 1o91m/tJ7cr/T1WtKlSm1Ep6KUjY/VSdeRALVqzTgtZErL0fxS/7C5/mPa+hNn4L
# Iyx7n3RMIlhIVCB+jVnSow0HybDbA0Ot8cwo2k9SALr5lH1bPkwuWej3UBoRFt1d
# 9FjfR+5F7ovp8u0oTaeXbsR2ynptv77KnLNzgUuW2N7CmH0qVDxumwoLf7aEDmwJ
# 3bEMn1Ipg0AvPo24WupBYuLowQGr4MbexUWmJJlTUpJ4Ol5p9ffZOFOHkyb0VGwh
# 0FbKkhYvAIhZVINteuYdem/5roXma1ibylSjd/Mwvw==
# SIG # End signature block
