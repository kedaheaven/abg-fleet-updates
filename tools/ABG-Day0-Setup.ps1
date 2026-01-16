<# 
ABG-Day0-Setup.ps1
Day 0 bootstrap for a new bay PC (AllSigned-friendly) + optional Dataverse ConfigItem registration.

Run as Administrator.

Example:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\ABG-Day0-Setup.ps1 `
  -FleetRawBaseUrl "https://raw.githubusercontent.com/kedaheaven/abg-fleet-updates/main" `
  -BayKioskUser "BayKiosk" `
  -RegisterConfigItems `
  -EnvironmentUrl "https://builds-apps-dev.crm.dynamics.com" `
  -TenantId "<tenant-guid>" `
  -ClientId "<app-client-id>" `
  -ClientSecretDpapiPath "C:\AllBirdies\BayAgent\secrets\clientsecret.dpapi" `
  -BayId "<bay-guid>"

Notes:
- Uses client_credentials token scope: <EnvironmentUrl>/.default
- Creates ConfigItem records (upsert) for thumbprint + key unique name.
#>

[CmdletBinding()]
param(
  [string]$AllBirdiesRoot = "C:\AllBirdies",
  [string]$BayKioskUser = "BayKiosk",

  # Raw GitHub base for downloading scripts
  [Parameter(Mandatory=$true)]
  [string]$FleetRawBaseUrl,

  # Scheduled tasks
  [switch]$CreateAgentTask = $false,
  [string]$BayKioskPassword = "",
  [switch]$CreateWatchdogTask = $true,

  # Cert subject
  [string]$CertSubject = "CN=ABG Bay Code Signing",

  # Config template
  [switch]$WriteAgentConfigTemplate = $true,

  # ---- NEW: Dataverse ConfigItem registration ----
  [switch]$RegisterConfigItems = $false,
  [string]$EnvironmentUrl = "",
  [string]$TenantId = "",
  [string]$ClientId = "",
  [string]$ClientSecretDpapiPath = "",
  [string]$BayId = "",

  # Entity set + field logical names (defaults match your schema screenshots)
  [string]$ConfigItemEntitySet = "build_configitems",
  [string]$ConfigItemIdField = "build_configitemid",
  [string]$Cfg_KeyField = "build_key",
  [string]$Cfg_ValueField = "build_value",
  [string]$Cfg_EnabledField = "build_enabled",
  [string]$Cfg_ScopeField = "build_scope",
  [string]$Cfg_BayLookupField = "build_bay",      # lookup logical name
  [string]$BayEntitySet = "build_bays"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Ensure-Dir([string]$p) {
  if (-not (Test-Path -LiteralPath $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
}

function Write-Step($msg) { Write-Host ("`n=== {0} ===" -f $msg) }

function Download-File([string]$url, [string]$outPath) {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  Ensure-Dir (Split-Path -Parent $outPath)
  Write-Host "Downloading: $url"
  Invoke-WebRequest -Uri $url -OutFile $outPath -UseBasicParsing -MaximumRedirection 10
  if (-not (Test-Path -LiteralPath $outPath)) { throw "Download failed: $outPath" }
}

function Get-CodeSigningCertOrCreate() {
  $existing = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object {
      $_.EnhancedKeyUsageList.FriendlyName -contains "Code Signing" -and
      $_.HasPrivateKey -and
      $_.Subject -like "*ABG*"
    } | Sort-Object NotAfter -Descending)

  if ($existing.Count -gt 0) {
    Write-Host "Found existing code signing cert: $($existing[0].Subject) Thumbprint=$($existing[0].Thumbprint)"
    return $existing[0]
  }

  Write-Host "Creating new code signing cert: $CertSubject"
  $cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject $CertSubject `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -HashAlgorithm sha256 `
    -KeyLength 2048

  if (-not $cert.HasPrivateKey) { throw "Created cert but no private key present." }
  Write-Host "Created cert Thumbprint=$($cert.Thumbprint) NotAfter=$($cert.NotAfter)"

  # Trust it on this machine
  $tmpCer = Join-Path $env:TEMP "abg-bay-codesign.cer"
  Export-Certificate -Cert "Cert:\LocalMachine\My\$($cert.Thumbprint)" -FilePath $tmpCer | Out-Null
  Import-Certificate -FilePath $tmpCer -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" | Out-Null
  Import-Certificate -FilePath $tmpCer -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null

  Write-Host "TrustedPublisher + Root updated."
  return $cert
}

function Get-CertUniqueContainerName([string]$thumbprint) {
  $out = (certutil -store My $thumbprint) 2>&1 | Out-String
  $match = [regex]::Match($out, "Unique container name:\s*(.+)")
  if (-not $match.Success) { throw "Could not find 'Unique container name' in certutil output.`n$out" }
  return $match.Groups[1].Value.Trim()
}

function Grant-Kiosk-KeyAccess([string]$uniqueName, [string]$kioskAccount) {
  $keyPath = Join-Path $env:ProgramData ("Microsoft\Crypto\Keys\{0}" -f $uniqueName)
  if (-not (Test-Path -LiteralPath $keyPath)) { throw "Key file not found: $keyPath" }

  Write-Host "Granting $kioskAccount read access to key file:"
  Write-Host "  $keyPath"
  icacls "$keyPath" /grant "${kioskAccount}:(R)" | Out-Null

  Write-Host "Key ACL now:"
  icacls "$keyPath"
}

function Sign-File([string]$path, $cert) {
  if (-not (Test-Path -LiteralPath $path)) { throw "Cannot sign missing file: $path" }
  Set-AuthenticodeSignature -FilePath $path -Certificate $cert | Out-Null
  $sig = Get-AuthenticodeSignature $path
  if ($sig.Status -ne "Valid") { throw "Signature invalid for $path. Status=$($sig.Status) Message=$($sig.StatusMessage)" }
}

function Write-AgentConfigTemplateIfMissing([string]$path) {
  if (Test-Path -LiteralPath $path) { Write-Host "agent-config.json exists; not overwriting."; return }

  $template = @"
{
  "environmentUrl": "https://<your-org>.crm.dynamics.com",
  "tenantId": "<tenant-guid>",
  "clientId": "<app-client-id>",
  "clientSecretDpapiPath": "C:\\AllBirdies\\BayAgent\\secrets\\clientsecret.dpapi",
  "bayId": "<bay-guid>",
  "pollSeconds": 3,
  "heartbeatSeconds": 60,
  "heartbeatEnabled": true,
  "postSessionThanksSeconds": 120,
  "postSessionThanksEnabled": true,
  "knownGoodSeconds": 60,
  "logLevel": "INFO",
  "sessionJsonPath": "C:\\AllBirdies\\SessionDisplay\\data\\session.json",
  "launcher": {
    "path": "C:\\Uneekor\\Launcher\\UneekorLauncher.exe",
    "args": "",
    "processName": "UneekorLauncher",
    "displayRole": "control",
    "startOnPrep": false,
    "startOnStart": true
  },
  "sessionDisplay": {
    "mode": "kiosk",
    "displayRole": "session",
    "url": "file:///C:/AllBirdies/SessionDisplay/current/index.html",
    "profileDir": "C:\\AllBirdies\\SessionDisplay\\edge-profile"
  }
}
"@
  Ensure-Dir (Split-Path -Parent $path)
  $template | Set-Content -LiteralPath $path -Encoding UTF8
  Write-Host "Wrote agent-config.json template to: $path"
}

function Ensure-SessionDisplayPersistentFiles([string]$dataDir) {
  Ensure-Dir $dataDir
  $sessionJson = Join-Path $dataDir "session.json"
  $promosJson  = Join-Path $dataDir "promos.json"
  if (-not (Test-Path $sessionJson)) { '{"status":"idle","updatedUtc":""}' | Set-Content -LiteralPath $sessionJson -Encoding UTF8 }
  if (-not (Test-Path $promosJson))  { '{ "items": [] }' | Set-Content -LiteralPath $promosJson  -Encoding UTF8 }
}

function Create-WatchdogTask([string]$watchdogPath) {
  $tn = "\ABG Host Watchdog"
  $tr = "powershell.exe -NoProfile -File `"$watchdogPath`""
  schtasks /Create /F /TN $tn /SC MINUTE /MO 1 /RU "SYSTEM" /RL HIGHEST /TR $tr | Out-Null
  Write-Host "Created/updated scheduled task: $tn (SYSTEM, every 1 minute)"
}

function Create-AgentTask([string]$agentHostPath, [string]$kioskAccount, [string]$kioskPassword) {
  $tn = "\ABG Bay Agent"
  $tr = "powershell.exe -NoProfile -WindowStyle Minimized -File `"$agentHostPath`""

  if ([string]::IsNullOrWhiteSpace($kioskPassword)) {
    Write-Host "Skipping automatic creation of $tn because BayKioskPassword was not provided."
    Write-Host "Use this command (run as Admin) once you have the password:"
    Write-Host ("schtasks /Create /F /TN `"{0}`" /SC ONLOGON /RU `"{1}`" /RP `"<password>`" /IT /TR `"{2}`"" -f $tn, $kioskAccount, $tr)
    return
  }

  schtasks /Create /F /TN $tn /SC ONLOGON /RU $kioskAccount /RP $kioskPassword /IT /TR $tr | Out-Null
  Write-Host "Created/updated scheduled task: $tn (ONLOGON for $kioskAccount, Interactive)"
}

# ---------- Dataverse helpers (NEW) ----------

function Get-ClientSecretFromDpapiFile([string]$path) {
  if (-not (Test-Path -LiteralPath $path)) { throw "DPAPI secret file not found: $path" }
  Add-Type -AssemblyName System.Security | Out-Null
  $bytes = [System.IO.File]::ReadAllBytes($path)
  $plain = [System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
  return [System.Text.Encoding]::UTF8.GetString($plain)
}

function Get-DataverseToken([string]$envUrl, [string]$tenantId, [string]$clientId, [string]$clientSecret) {
  $tokenUrl = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
  $body = @{
    client_id     = $clientId
    client_secret = $clientSecret
    grant_type    = "client_credentials"
    scope         = ($envUrl.TrimEnd("/") + "/.default")
  }
  $resp = Invoke-RestMethod -Method Post -Uri $tokenUrl -ContentType "application/x-www-form-urlencoded" -Body $body
  if (-not $resp.access_token) { throw "Token request did not return access_token." }
  return $resp.access_token
}

function Invoke-Dv([string]$method, [string]$envUrl, [string]$path, [string]$token, $body = $null) {
  $uri = $envUrl.TrimEnd("/") + "/api/data/v9.2/" + $path.TrimStart("/")
  $headers = @{
    Authorization    = "Bearer $token"
    "OData-MaxVersion" = "4.0"
    "OData-Version"    = "4.0"
    Accept            = "application/json"
  }
  if ($method -in @("POST","PATCH","PUT")) {
    $headers["Content-Type"] = "application/json; charset=utf-8"
  }
  if ($null -eq $body) {
    return Invoke-RestMethod -Method $method -Uri $uri -Headers $headers
  } else {
    $json = ($body | ConvertTo-Json -Depth 20)
    return Invoke-RestMethod -Method $method -Uri $uri -Headers $headers -Body $json
  }
}

function Get-ChoiceValueByLabel([string]$envUrl, [string]$token, [string]$entityLogical, [string]$attrLogical, [string]$labelToFind) {
  # Fetch picklist metadata for the attribute
  $metaPath = "EntityDefinitions(LogicalName='$entityLogical')/Attributes(LogicalName='$attrLogical')/Microsoft.Dynamics.CRM.PicklistAttributeMetadata?`$select=LogicalName&`$expand=OptionSet(`$select=Options)"
  $meta = Invoke-Dv -method "GET" -envUrl $envUrl -path $metaPath -token $token

  $options = $meta.OptionSet.Options
  foreach ($opt in $options) {
    foreach ($lbl in $opt.Label.LocalizedLabels) {
      if ($lbl.Label -eq $labelToFind) { return [int]$opt.Value }
    }
  }
  throw "Could not find option label '$labelToFind' for $entityLogical.$attrLogical"
}

function Upsert-ConfigItemForBay([string]$envUrl, [string]$token, [guid]$bayGuid, [int]$scopeValue, [string]$keyName, [string]$val) {
  # Query existing record by Bay + Key
  $filter = "$Cfg_KeyField eq '$keyName' and _${Cfg_BayLookupField}_value eq $bayGuid"
  $qry = "$ConfigItemEntitySet?`$select=$ConfigItemIdField&`$filter=$filter"
  $res = Invoke-Dv -method "GET" -envUrl $envUrl -path $qry -token $token

  $payload = @{
    $Cfg_KeyField     = $keyName
    $Cfg_ValueField   = $val
    $Cfg_EnabledField = $true
    $Cfg_ScopeField   = $scopeValue
    ("$Cfg_BayLookupField@odata.bind") = "/$BayEntitySet($bayGuid)"
  }

  if ($res.value -and $res.value.Count -gt 0) {
    $id = $res.value[0].$ConfigItemIdField
    Invoke-Dv -method "PATCH" -envUrl $envUrl -path "$ConfigItemEntitySet($id)" -token $token -body $payload | Out-Null
    Write-Host "Updated ConfigItem: $keyName"
  } else {
    Invoke-Dv -method "POST" -envUrl $envUrl -path $ConfigItemEntitySet -token $token -body $payload | Out-Null
    Write-Host "Created ConfigItem: $keyName"
  }
}

# ---------------- MAIN ----------------

Write-Step "Folder structure"
$bayAgentDir   = Join-Path $AllBirdiesRoot "BayAgent"
$sessionDir    = Join-Path $AllBirdiesRoot "SessionDisplay"

@(
  $bayAgentDir,
  (Join-Path $bayAgentDir "bootstrap"),
  (Join-Path $bayAgentDir "tools"),
  (Join-Path $bayAgentDir "current"),
  (Join-Path $bayAgentDir "releases"),
  (Join-Path $bayAgentDir "staging"),
  (Join-Path $bayAgentDir "logs"),
  (Join-Path $bayAgentDir "state"),
  (Join-Path $bayAgentDir "control"),
  (Join-Path $bayAgentDir "secrets")
) | ForEach-Object { Ensure-Dir $_ }

@(
  $sessionDir,
  (Join-Path $sessionDir "current"),
  (Join-Path $sessionDir "releases"),
  (Join-Path $sessionDir "staging"),
  (Join-Path $sessionDir "data"),
  (Join-Path $sessionDir "edge-profile")
) | ForEach-Object { Ensure-Dir $_ }

Ensure-SessionDisplayPersistentFiles -dataDir (Join-Path $sessionDir "data")

Write-Step "Download bootstrap/tools scripts"
$agentHostPath   = Join-Path $bayAgentDir "bootstrap\ABG.AgentHost.ps1"
$watchdogPath    = Join-Path $bayAgentDir "bootstrap\ABG.HostWatchdog.ps1"
$updateAgentPath = Join-Path $bayAgentDir "tools\Update-BayAgent.ps1"
$updateDispPath  = Join-Path $bayAgentDir "tools\Update-SessionDisplay.ps1"

Download-File -url ($FleetRawBaseUrl.TrimEnd("/") + "/bootstrap/ABG.AgentHost.ps1")       -outPath $agentHostPath
Download-File -url ($FleetRawBaseUrl.TrimEnd("/") + "/bootstrap/ABG.HostWatchdog.ps1")   -outPath $watchdogPath
Download-File -url ($FleetRawBaseUrl.TrimEnd("/") + "/tools/Update-BayAgent.ps1")        -outPath $updateAgentPath
Download-File -url ($FleetRawBaseUrl.TrimEnd("/") + "/tools/Update-SessionDisplay.ps1") -outPath $updateDispPath

Write-Step "Create/trust code-signing certificate"
$cert = Get-CodeSigningCertOrCreate

Write-Step "Grant BayKiosk access to private key file (Crypto\\Keys)"
$kioskAccount = "$env:COMPUTERNAME\$BayKioskUser"
$uniqueName = Get-CertUniqueContainerName -thumbprint $cert.Thumbprint
Write-Host "Unique container name: $uniqueName"
Grant-Kiosk-KeyAccess -uniqueName $uniqueName -kioskAccount $kioskAccount

Write-Step "Sign bootstrap/tools scripts"
Sign-File -path $agentHostPath   -cert $cert
Sign-File -path $watchdogPath    -cert $cert
Sign-File -path $updateAgentPath -cert $cert
Sign-File -path $updateDispPath  -cert $cert
Write-Host "All bootstrap/tools scripts signed and valid."

Write-Step "Write agent-config.json template (if missing)"
if ($WriteAgentConfigTemplate) {
  $cfgPath = Join-Path $bayAgentDir "agent-config.json"
  Write-AgentConfigTemplateIfMissing -path $cfgPath
}

Write-Step "Scheduled tasks"
if ($CreateWatchdogTask) { Create-WatchdogTask -watchdogPath $watchdogPath }
if ($CreateAgentTask)    { Create-AgentTask -agentHostPath $agentHostPath -kioskAccount $kioskAccount -kioskPassword $BayKioskPassword }

# ---- NEW: Dataverse registration ----
if ($RegisterConfigItems) {
  Write-Step "Dataverse: Register per-bay ConfigItems (thumbprint + key unique name)"

  if ([string]::IsNullOrWhiteSpace($EnvironmentUrl) -or
      [string]::IsNullOrWhiteSpace($TenantId) -or
      [string]::IsNullOrWhiteSpace($ClientId) -or
      [string]::IsNullOrWhiteSpace($ClientSecretDpapiPath) -or
      [string]::IsNullOrWhiteSpace($BayId)) {
    throw "RegisterConfigItems set, but missing one of: EnvironmentUrl, TenantId, ClientId, ClientSecretDpapiPath, BayId"
  }

  $bayGuid = [guid]$BayId

  $secret = Get-ClientSecretFromDpapiFile -path $ClientSecretDpapiPath
  $token  = Get-DataverseToken -envUrl $EnvironmentUrl -tenantId $TenantId -clientId $ClientId -clientSecret $secret

  # Get Scope option value by label "Bay" from metadata (no hardcoding)
  $scopeBayValue = Get-ChoiceValueByLabel -envUrl $EnvironmentUrl -token $token -entityLogical "build_configitem" -attrLogical $Cfg_ScopeField -labelToFind "Bay"
  Write-Host "Resolved ConfigItem scope 'Bay' option value: $scopeBayValue"

  Upsert-ConfigItemForBay -envUrl $EnvironmentUrl -token $token -bayGuid $bayGuid -scopeValue $scopeBayValue `
    -keyName "Agent.CodeSigningThumbprint" -val $cert.Thumbprint

  Upsert-ConfigItemForBay -envUrl $EnvironmentUrl -token $token -bayGuid $bayGuid -scopeValue $scopeBayValue `
    -keyName "Agent.CodeSigningKeyUniqueName" -val $uniqueName

  Write-Host "Dataverse ConfigItems registered successfully."
}

Write-Step "BayKiosk signing smoke test instructions"
Write-Host "Log in as $kioskAccount and run:"
Write-Host '  $tp = "' + $cert.Thumbprint + '"'
Write-Host '  $cert = Get-ChildItem "Cert:\LocalMachine\My\$tp"'
Write-Host '  $test = "C:\AllBirdies\BayAgent\state\sign-test.ps1"'
Write-Host '  "Write-Output ''sign test ok''" | Set-Content -Path $test -Encoding UTF8'
Write-Host '  Set-AuthenticodeSignature -FilePath $test -Certificate $cert | Out-Null'
Write-Host '  Get-AuthenticodeSignature $test | Format-List Status, StatusMessage'

Write-Step "DONE"
Write-Host "BayAgent root: $bayAgentDir"
Write-Host "SessionDisplay root: $sessionDir"
Write-Host "Code signing thumbprint: $($cert.Thumbprint)"
Write-Host "Key unique name: $uniqueName"
Write-Host "Kiosk key ACL granted to: $kioskAccount"