<#
BayAgent.Credential.Tests.ps1

Exercises the certificate-credential path of src\BayAgent\BayAgent.ps1 WITHOUT running the agent:
the credential functions are lifted out of the script by AST and run against
  - a throwaway self-signed certificate created in Cert:\CurrentUser\My (deleted at the end), and
  - a LOCAL MOCK token endpoint (a TcpListener on 127.0.0.1 in a background runspace) that records
    every request the agent sends and answers with whatever the test tells it to.

What the mock proves and what it does not:
  PROVES   the exact form body the agent posts (client_assertion_type, client_assertion, scope, client_id,
           grant_type), that the assertion verifies against the certificate's public key, the aud/iss/sub/
           jti/nbf/exp claims, the token-cache behaviour, the secret FALLBACK on a certificate failure,
           the activate-only-after-proof rule, and the retire guards.
  DOES NOT prove that Entra accepts the assertion. The -Live switch adds one real check with no Azure
           write: an assertion signed by the UNREGISTERED test certificate is posted to the real Entra
           endpoint for the real app id, and Entra is expected to answer AADSTS700027 (signature valid
           in form, key not found) rather than a malformed-assertion error.

Run (from the repo root):
  powershell -NoProfile -ExecutionPolicy Bypass -File tests\BayAgent.Credential.Tests.ps1
  powershell -NoProfile -ExecutionPolicy Bypass -File tests\BayAgent.Credential.Tests.ps1 -Live
Exit code 0 = all assertions passed. Hyphens only in comments (em-dashes break AllSigned parsing).
#>
[CmdletBinding()]
param(
    [switch]$Live,
    [string]$AgentScript = "",
    # Real values used ONLY by -Live (no writes: a token request with an unregistered key is rejected).
    [string]$LiveTenantId = "cc551e6a-be6a-42d2-add4-231f5891a179",
    [string]$LiveClientId = "0e77dbf6-499d-434c-acfc-b276bc439c38",
    [string]$LiveOrgUrl   = "https://builds-apps-dev.crm.dynamics.com",
    [string]$LiveForeignTenantId = "9c568879-aa66-44cd-b5c0-a2ce64adc958"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
try { Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue } catch {}
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

if ([string]::IsNullOrWhiteSpace($AgentScript)) { $AgentScript = Join-Path $PSScriptRoot "..\src\BayAgent\BayAgent.ps1" }
$AgentScript = (Resolve-Path $AgentScript).Path

# ---------------------------------------------------------------- harness
$script:Pass = 0; $script:Fail = 0; $script:Failures = @()
function Assert-True([bool]$cond, [string]$msg) {
    if ($cond) { $script:Pass++; Write-Host "  PASS  $msg" }
    else { $script:Fail++; $script:Failures += $msg; Write-Host "  FAIL  $msg" -ForegroundColor Red }
}
function Assert-Throws([scriptblock]$sb, [string]$pattern, [string]$msg) {
    $threw = $false; $text = ""
    try { & $sb | Out-Null } catch { $threw = $true; $text = $_.Exception.Message }
    if (-not $threw) { Assert-True $false "$msg (did NOT throw)"; return }
    Assert-True ($text -match $pattern) "$msg (threw: $text)"
}
function Section([string]$name) { Write-Host ""; Write-Host "== $name" -ForegroundColor Cyan }

# ---------------------------------------------------------------- lift functions out of BayAgent.ps1
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($AgentScript, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw "BayAgent.ps1 has parse errors: $($errors | ForEach-Object { $_.Message } | Out-String)" }

$wanted = @(
    "Read-WebExceptionBody", "Get-ClientSecret", "Get-PropValue",
    "ConvertTo-Base64Url", "ConvertFrom-Base64Url", "Normalize-Thumbprint",
    "Read-CredentialState", "Write-CredentialState", "Update-CredentialState",
    "Get-ActiveCertThumbprint", "Get-PendingCertThumbprint", "Get-CertStoreSearchOrder", "Get-CertStoreName",
    "Find-ClientCertificate", "New-ClientAssertionJwt", "Get-AadstsCode", "Get-TokenUrl", "Invoke-TokenEndpoint",
    "Acquire-TokenWithCertificate", "Acquire-TokenWithSecret", "Acquire-Token", "Get-CredentialTelemetry",
    "Write-CredentialStartupSummary", "Get-AccessToken",
    "New-BayClientCertificate", "Export-PublicCertificate", "Build-CredentialEnrollResult",
    "Invoke-CredentialEnroll", "Invoke-CredentialTest", "Invoke-CredentialActivate", "Invoke-CredentialRetire",
    "Invoke-CredentialStatus", "Invoke-CredentialRotate",
    "Limit-ResultJson", "New-BayClientCertificate"
)
$defs = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
$lifted = 0
foreach ($name in $wanted) {
    $d = $defs | Where-Object { $_.Name -eq $name } | Select-Object -First 1
    if (-not $d) { throw "Function '$name' not found in $AgentScript" }
    . ([scriptblock]::Create($d.Extent.Text))
    $lifted++
}
Write-Host "Lifted $lifted functions from $AgentScript"

# Agent-side script variables the lifted functions read (mirrors the top of BayAgent.ps1).
$script:LogLines = New-Object System.Collections.ArrayList
function Write-Log { param([string]$Message, [string]$Level = "INFO") [void]$script:LogLines.Add("[$Level] $Message") }

$BaseDir = Join-Path $env:TEMP ("bayagent-credtest-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Force -Path (Join-Path $BaseDir "state") | Out-Null
$CredentialStatePath = Join-Path $BaseDir "state\credential.json"
$TenantId  = "11111111-1111-1111-1111-111111111111"
$ClientId  = "22222222-2222-2222-2222-222222222222"
$OrgUrl    = "https://mock-org.crm.dynamics.com"
$BayId     = "33333333-3333-3333-3333-333333333333"
$TokenAuthorityHost  = "http://127.0.0.1:1"      # replaced once the mock is up
$AssertionAlg        = "RS256"
$ResultJsonMaxChars  = 2000      # MEASURED against Dev: build_resultjson is Memo(2000)
$CertThumbprintCfg   = $null
$CertStoreCfg        = $null
$Secret              = $null
$SecretPath          = $null
$SecretPathCfg       = $null
$HasSecretCredential = $false
$Global:AccessToken     = $null
$Global:TokenExpiresUtc = [DateTime]::MinValue
$Global:CredentialTelemetry = @{
    lastMintMode = $null; lastMintUtc = $null; lastCertMintUtc = $null; lastSecretMintUtc = $null
    lastCertError = $null; lastSecretError = $null; fallbackCount = 0; lastTest = $null
}
$script:CreatedCerts = New-Object System.Collections.ArrayList

function Reset-TokenState {
    $Global:AccessToken = $null
    $Global:TokenExpiresUtc = [DateTime]::MinValue
}

# ---------------------------------------------------------------- mock token endpoint (background runspace)
function Start-MockTokenEndpoint([hashtable]$Sync) {
    $rs = [runspacefactory]::CreateRunspace()
    $rs.Open()
    $rs.SessionStateProxy.SetVariable("sync", $Sync)
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript({
        $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
        $listener.Start()
        $sync["Port"] = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
        try {
            while (-not $sync["Stop"]) {
                if (-not $listener.Server.Poll(200000, [System.Net.Sockets.SelectMode]::SelectRead)) { continue }
                $client = $listener.AcceptTcpClient()
                try {
                    $client.ReceiveTimeout = 5000
                    $stream = $client.GetStream()
                    $buf = New-Object byte[] 65536
                    $ms = New-Object System.IO.MemoryStream
                    $headerEnd = -1
                    while ($headerEnd -lt 0) {
                        $n = $stream.Read($buf, 0, $buf.Length)
                        if ($n -le 0) { break }
                        $ms.Write($buf, 0, $n)
                        $headerEnd = ([Text.Encoding]::ASCII.GetString($ms.ToArray())).IndexOf("`r`n`r`n")
                    }
                    $all = $ms.ToArray()
                    $headText = [Text.Encoding]::ASCII.GetString($all, 0, $headerEnd)
                    $contentLength = 0
                    if ($headText -match "(?im)^Content-Length:\s*(\d+)") { $contentLength = [int]$Matches[1] }
                    $bodyStart = $headerEnd + 4
                    while (($all.Length - $bodyStart) -lt $contentLength) {
                        $n = $stream.Read($buf, 0, $buf.Length)
                        if ($n -le 0) { break }
                        $ms.Write($buf, 0, $n)
                        $all = $ms.ToArray()
                    }
                    $body = [Text.Encoding]::UTF8.GetString($all, $bodyStart, [Math]::Min($contentLength, $all.Length - $bodyStart))
                    [void]$sync["Requests"].Add(@{ requestLine = (($headText -split "`r`n")[0]); headers = $headText; body = $body })
                    $resp = if ($body.Contains("client_assertion=")) { $sync["CertResponse"] } else { $sync["SecretResponse"] }
                    $status = [int]$resp.status
                    $reason = "OK"; if ($status -eq 401) { $reason = "Unauthorized" } elseif ($status -ge 400) { $reason = "Bad Request" }
                    $bytes = [Text.Encoding]::UTF8.GetBytes([string]$resp.body)
                    $head = "HTTP/1.1 $status $reason`r`nContent-Type: application/json; charset=utf-8`r`nContent-Length: $($bytes.Length)`r`nConnection: close`r`n`r`n"
                    $hb = [Text.Encoding]::ASCII.GetBytes($head)
                    $stream.Write($hb, 0, $hb.Length); $stream.Write($bytes, 0, $bytes.Length); $stream.Flush()
                } catch { [void]$sync["Errors"].Add($_.Exception.Message) }
                finally { $client.Close() }
            }
        } finally { $listener.Stop() }
    })
    $handle = $ps.BeginInvoke()
    return @{ PS = $ps; RS = $rs; Handle = $handle }
}

$sync = [hashtable]::Synchronized(@{
    Stop = $false; Port = 0
    Requests = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    Errors   = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    CertResponse   = @{ status = 200; body = '{"token_type":"Bearer","expires_in":3599,"access_token":"mock-cert-token"}' }
    SecretResponse = @{ status = 200; body = '{"token_type":"Bearer","expires_in":3599,"access_token":"mock-secret-token"}' }
})
$mock = Start-MockTokenEndpoint -Sync $sync
$deadline = (Get-Date).AddSeconds(10)
while ($sync["Port"] -eq 0 -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 50 }
if ($sync["Port"] -eq 0) { throw "mock token endpoint did not start" }
$TokenAuthorityHost = "http://127.0.0.1:$($sync['Port'])"
Write-Host "Mock token endpoint listening on $TokenAuthorityHost (this is a MOCK, not Entra)"

function Get-FormField([string]$body, [string]$name) {
    foreach ($kv in $body.Split("&")) {
        $i = $kv.IndexOf("=")
        if ($i -lt 0) { continue }
        if ($kv.Substring(0, $i) -eq $name) { return [uri]::UnescapeDataString($kv.Substring($i + 1)) }
    }
    return $null
}
function Get-JwtPart([string]$jwt, [int]$index) {
    return ([Text.Encoding]::UTF8.GetString((ConvertFrom-Base64Url $jwt.Split(".")[$index])) | ConvertFrom-Json)
}
function Test-JwtSignature([string]$jwt, $cert, [string]$alg = "RS256") {
    $parts = $jwt.Split(".")
    $data = [Text.Encoding]::UTF8.GetBytes("$($parts[0]).$($parts[1])")
    $sig = ConvertFrom-Base64Url $parts[2]
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert)
    $pad = if ($alg -eq "PS256") { [System.Security.Cryptography.RSASignaturePadding]::Pss } else { [System.Security.Cryptography.RSASignaturePadding]::Pkcs1 }
    return $rsa.VerifyData($data, $sig, [System.Security.Cryptography.HashAlgorithmName]::SHA256, $pad)
}

try {
    # ============================================================ T1: certificate creation + JWT shape
    Section "T1 enrollment creates a non-exportable key and the assertion has the documented shape"
    $cert = New-BayClientCertificate -Subject "CN=ABG-BayAgent credtest $BayId" -ValidityDays 30 -Store CurrentUser
    [void]$script:CreatedCerts.Add($cert.Thumbprint)
    Assert-True ($cert.HasPrivateKey) "certificate has a private key"
    Assert-True ((Get-CertStoreName $cert) -eq "CurrentUser\My") "certificate landed in CurrentUser\My (got '$(Get-CertStoreName $cert)')"
    $exportable = $true
    try { $null = $cert.PrivateKey.ExportParameters($true) } catch { $exportable = $false }
    try { $k = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert); $null = $k.ExportParameters($true); $exportable = $true } catch { $exportable = $false }
    Assert-True (-not $exportable) "private key is NOT exportable"
    Assert-True ($cert.NotAfter -gt (Get-Date).AddDays(29)) "validity honoured (NotAfter $($cert.NotAfter.ToString('u')))"

    $aud = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $jwt = New-ClientAssertionJwt -Certificate $cert -ClientId $ClientId -Audience $aud
    $parts = $jwt.Split(".")
    Assert-True ($parts.Count -eq 3) "JWT has three dot-separated parts"
    Assert-True (($jwt -notmatch "[=+/]")) "JWT uses base64url alphabet (no = + /)"
    $hdr = Get-JwtPart $jwt 0
    Assert-True ($hdr.alg -eq "RS256" -and $hdr.typ -eq "JWT") "header alg=RS256 typ=JWT"
    $expX5t = ConvertTo-Base64Url ([System.Security.Cryptography.SHA1]::Create().ComputeHash($cert.RawData))
    $expX5tS256 = ConvertTo-Base64Url ([System.Security.Cryptography.SHA256]::Create().ComputeHash($cert.RawData))
    Assert-True ($hdr.x5t -eq $expX5t) "header x5t = base64url(SHA-1 of DER) = thumbprint"
    Assert-True ($hdr.'x5t#S256' -eq $expX5tS256) "header x5t#S256 = base64url(SHA-256 of DER)"
    $tpFromX5t = -join ((ConvertFrom-Base64Url $hdr.x5t) | ForEach-Object { $_.ToString("X2") })
    Assert-True ($tpFromX5t -eq $cert.Thumbprint) "x5t decodes back to the certificate thumbprint"
    $claims = Get-JwtPart $jwt 1
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    Assert-True ($claims.aud -eq $aud) "aud = token endpoint URL"
    Assert-True ($claims.iss -eq $ClientId -and $claims.sub -eq $ClientId) "iss = sub = client id"
    Assert-True ([guid]::TryParse([string]$claims.jti, [ref]([guid]::Empty))) "jti is a GUID"
    Assert-True ($claims.nbf -le $now -and $claims.nbf -ge ($now - 120)) "nbf is now minus skew allowance"
    Assert-True ($claims.iat -le $now -and $claims.iat -ge ($now - 5)) "iat is now"
    Assert-True ($claims.exp -gt $now -and ($claims.exp - $claims.nbf) -le 600) "exp is short-lived (exp-nbf = $($claims.exp - $claims.nbf)s, documented max 600s)"
    Assert-True (Test-JwtSignature $jwt $cert) "RS256 signature verifies with the certificate public key"
    $tampered = $parts[0] + "." + $parts[1].Substring(0, $parts[1].Length - 2) + "AA." + $parts[2]
    Assert-True (-not (Test-JwtSignature $tampered $cert)) "tampered payload fails signature verification"
    $jwt2 = New-ClientAssertionJwt -Certificate $cert -ClientId $ClientId -Audience $aud
    Assert-True ((Get-JwtPart $jwt2 1).jti -ne $claims.jti) "each assertion carries a fresh jti"
    $jwtPs = New-ClientAssertionJwt -Certificate $cert -ClientId $ClientId -Audience $aud -Alg "PS256"
    Assert-True ((Get-JwtPart $jwtPs 0).alg -eq "PS256" -and (Test-JwtSignature $jwtPs $cert "PS256")) "PS256 variant signs with PSS padding and verifies"

    # ============================================================ T2: certificate mint against the mock
    Section "T2 Acquire-Token uses the ACTIVE certificate: form body, assertion, cache (MOCK endpoint)"
    Update-CredentialState @{ activeThumbprint = $cert.Thumbprint } | Out-Null
    Assert-True ((Get-ActiveCertThumbprint) -eq $cert.Thumbprint) "state\credential.json activeThumbprint is honoured"
    $sync["Requests"].Clear(); Reset-TokenState
    $tok = Get-AccessToken
    Assert-True ($tok -eq "mock-cert-token") "token returned from the certificate path"
    Assert-True ($sync["Requests"].Count -eq 1) "exactly one token request sent"
    $req = $sync["Requests"][0]
    Assert-True ($req.requestLine -eq "POST /$TenantId/oauth2/v2.0/token HTTP/1.1") "POST to /{tenant}/oauth2/v2.0/token (got '$($req.requestLine)')"
    Assert-True ($req.headers -match "(?im)^Content-Type:\s*application/x-www-form-urlencoded") "form-encoded body"
    $body = $req.body
    Assert-True ((Get-FormField $body "grant_type") -eq "client_credentials") "grant_type=client_credentials"
    Assert-True ((Get-FormField $body "client_assertion_type") -eq "urn:ietf:params:oauth:client-assertion-type:jwt-bearer") "client_assertion_type=jwt-bearer"
    Assert-True ((Get-FormField $body "client_id") -eq $ClientId) "client_id present"
    Assert-True ((Get-FormField $body "scope") -eq "$OrgUrl/.default") "scope={orgUrl}/.default"
    Assert-True ($null -eq (Get-FormField $body "client_secret")) "NO client_secret in the certificate request"
    $sentJwt = Get-FormField $body "client_assertion"
    Assert-True (Test-JwtSignature $sentJwt $cert) "sent assertion verifies with the certificate public key"
    Assert-True ((Get-JwtPart $sentJwt 1).aud -eq "$TokenAuthorityHost/$TenantId/oauth2/v2.0/token") "aud matches the endpoint actually posted to"
    Assert-True ($Global:CredentialTelemetry.lastMintMode -eq "certificate") "telemetry lastMintMode=certificate"
    Assert-True ($Global:CredentialTelemetry.fallbackCount -eq 0) "no fallback counted"
    $expectedExp = (Get-Date).ToUniversalTime().AddSeconds(3599 - 300)
    Assert-True ([Math]::Abs(($Global:TokenExpiresUtc - $expectedExp).TotalSeconds) -lt 10) "cache expiry = expires_in - 300s"
    $tok2 = Get-AccessToken
    Assert-True ($tok2 -eq "mock-cert-token" -and $sync["Requests"].Count -eq 1) "second call served from cache (no new request)"

    # ============================================================ T3: fallback to the secret on certificate failure
    Section "T3 certificate failure falls back to the client secret, loudly (MOCK endpoint)"
    $sync["CertResponse"] = @{ status = 401; body = '{"error":"invalid_client","error_description":"AADSTS700027: Client assertion contains an invalid signature. [Reason - The key was not found.]"}' }
    $Secret = "mock-secret-value"; $HasSecretCredential = $true
    $sync["Requests"].Clear(); $script:LogLines.Clear(); Reset-TokenState
    $tok = Acquire-Token
    Assert-True ($tok -eq "mock-secret-token") "token returned from the secret path"
    Assert-True ($sync["Requests"].Count -eq 2) "two requests: certificate attempt then secret attempt"
    Assert-True ($sync["Requests"][0].body.Contains("client_assertion=")) "first attempt was the certificate"
    Assert-True ((Get-FormField $sync["Requests"][1].body "client_secret") -eq "mock-secret-value") "second attempt carried the secret"
    Assert-True ($Global:CredentialTelemetry.lastMintMode -eq "secret") "telemetry lastMintMode=secret"
    Assert-True ($Global:CredentialTelemetry.fallbackCount -eq 1) "fallback counted"
    Assert-True (([string]$Global:CredentialTelemetry.lastCertError).Contains("AADSTS700027")) "lastCertError carries the AADSTS code"
    Assert-True ((($script:LogLines | Where-Object { $_ -match "^\[WARN\].*falling back" }) | Measure-Object).Count -eq 1) "fallback logged at WARN"
    Assert-True ((($script:LogLines | Where-Object { $_ -match "mock-secret-value" }) | Measure-Object).Count -eq 0) "secret value never logged"

    # ============================================================ T4: no fallback available -> hard failure
    Section "T4 certificate failure with no secret configured throws (nothing silently succeeds)"
    $Secret = $null; $HasSecretCredential = $false
    $sync["Requests"].Clear(); Reset-TokenState
    Assert-Throws { Acquire-Token } "HTTP 401.*AADSTS700027" "Acquire-Token throws with the HTTP status and AADSTS code"
    Assert-True ($null -eq $Global:AccessToken) "no token cached after failure"
    Assert-True ($sync["Requests"].Count -eq 1) "only the certificate attempt was made"

    # ============================================================ T5: secret-only bay (today's Bay 1) is unchanged
    Section "T5 secret-only configuration (no certificate) keeps the original client_secret request"
    Remove-Item -LiteralPath $CredentialStatePath -Force
    $CertThumbprintCfg = $null
    $Secret = "mock-secret-value"; $HasSecretCredential = $true
    $sync["Requests"].Clear(); Reset-TokenState
    $before = $Global:CredentialTelemetry.fallbackCount
    $tok = Get-AccessToken
    Assert-True ($tok -eq "mock-secret-token") "token from the secret path"
    Assert-True ($sync["Requests"].Count -eq 1 -and -not $sync["Requests"][0].body.Contains("client_assertion")) "single client_secret request, no assertion"
    Assert-True ((Get-FormField $sync["Requests"][0].body "grant_type") -eq "client_credentials" -and (Get-FormField $sync["Requests"][0].body "scope") -eq "$OrgUrl/.default") "secret request body unchanged"
    Assert-True ($Global:CredentialTelemetry.fallbackCount -eq $before) "not counted as a fallback"
    Assert-True ((Get-CredentialTelemetry).configuredMode -eq "secret") "telemetry configuredMode=secret"

    # ============================================================ T6: enroll is PENDING on a credentialed bay; activate proves first
    Section "T6 enroll -> pending; activate switches ONLY after a successful mint (MOCK endpoint)"
    $sync["CertResponse"] = @{ status = 401; body = '{"error":"invalid_client","error_description":"AADSTS700027: Client assertion contains an invalid signature. [Reason - The key was not found.]"}' }
    $enroll = Invoke-CredentialRotate ([pscustomobject]@{ action = "enroll"; validityDays = 45; subject = "CN=ABG-BayAgent credtest2 $BayId" })
    [void]$script:CreatedCerts.Add($enroll.thumbprint)
    Assert-True ($enroll.ok -and -not $enroll.activatedDirectly -and -not $enroll.reused) "enroll on a bay with a secret returns a PENDING certificate"
    Assert-True ((Get-PendingCertThumbprint) -eq $enroll.thumbprint) "state pendingThumbprint set"
    Assert-True ($null -eq (Get-ActiveCertThumbprint)) "active credential unchanged (none)"
    Assert-True ((Test-Path $enroll.publicCertPath) -and ([IO.File]::ReadAllBytes($enroll.publicCertPath).Length -gt 200)) "public .cer written to state\"
    $pub = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (,[Convert]::FromBase64String($enroll.publicCertBase64))
    Assert-True ($pub.Thumbprint -eq $enroll.thumbprint -and -not $pub.HasPrivateKey) "publicCertBase64 is the public half only"
    $again = Invoke-CredentialRotate ([pscustomobject]@{ action = "enroll" })
    Assert-True ($again.reused -and $again.thumbprint -eq $enroll.thumbprint) "a retried enroll is idempotent (returns the pending cert, no new key)"

    $stateBefore = Get-Content -LiteralPath $CredentialStatePath -Raw
    Assert-Throws { Invoke-CredentialRotate ([pscustomobject]@{ action = "activate" }) } "AADSTS700027" "activate FAILS when the pending certificate cannot mint"
    Assert-True ((Get-Content -LiteralPath $CredentialStatePath -Raw) -eq $stateBefore) "state untouched after failed activate"
    Assert-True ($null -eq (Get-ActiveCertThumbprint)) "active credential still unchanged"

    $test = Invoke-CredentialRotate ([pscustomobject]@{ action = "test"; includeSecret = $true })
    Assert-True (-not $test.ok -and -not $test.certificate.ok -and $test.secret.ok) "test reports certificate=fail, secret=ok while the key is unregistered"

    $sync["CertResponse"] = @{ status = 200; body = '{"token_type":"Bearer","expires_in":3599,"access_token":"mock-cert-token-2"}' }
    $Global:AccessToken = "stale-cached-token"; $Global:TokenExpiresUtc = (Get-Date).ToUniversalTime().AddMinutes(30)
    $act = Invoke-CredentialRotate ([pscustomobject]@{ action = "activate" })
    Assert-True ($act.ok -and $act.activeThumbprint -eq $enroll.thumbprint -and $act.proof.mintedWithCertificate) "activate succeeds after a live proof mint"
    Assert-True ((Get-ActiveCertThumbprint) -eq $enroll.thumbprint -and $null -eq (Get-PendingCertThumbprint)) "state: active=new, pending cleared"
    Assert-True ($null -eq $Global:AccessToken) "cached token dropped so the next loop mints with the new certificate"
    $sync["Requests"].Clear()
    $tok = Get-AccessToken
    Assert-True ($tok -eq "mock-cert-token-2") "next mint uses the certificate"
    $sentJwt = Get-FormField $sync["Requests"][0].body "client_assertion"
    Assert-True ((Get-JwtPart $sentJwt 0).x5t -eq (ConvertTo-Base64Url ([System.Security.Cryptography.SHA1]::Create().ComputeHash($pub.RawData)))) "assertion signed by the NEW certificate"

    # ============================================================ T7: retire guards
    Section "T7 retire never removes the active credential; secret retire needs a live certificate proof"
    Assert-Throws { Invoke-CredentialRotate ([pscustomobject]@{ action = "retire"; thumbprint = $enroll.thumbprint }) } "ACTIVE credential" "retiring the active certificate is refused"
    $dpapiFile = Join-Path $BaseDir "secrets\clientsecret.dpapi"
    New-Item -ItemType Directory -Force -Path (Split-Path $dpapiFile) | Out-Null
    [IO.File]::WriteAllBytes($dpapiFile, [byte[]](1, 2, 3))
    $Secret = $null; $SecretPath = $dpapiFile; $SecretPathCfg = $dpapiFile; $HasSecretCredential = $true
    $sync["CertResponse"] = @{ status = 401; body = '{"error":"invalid_client","error_description":"AADSTS700027: key not found"}' }
    Assert-Throws { Invoke-CredentialRotate ([pscustomobject]@{ action = "retire"; secret = $true }) } "AADSTS700027" "secret retire refused while the active certificate cannot mint"
    Assert-True (Test-Path $dpapiFile) "DPAPI file untouched after refused retire"
    $sync["CertResponse"] = @{ status = 200; body = '{"token_type":"Bearer","expires_in":3599,"access_token":"mock-cert-token-2"}' }
    $ret = Invoke-CredentialRotate ([pscustomobject]@{ action = "retire"; secret = $true; thumbprint = $cert.Thumbprint })
    Assert-True ($ret.ok -and $ret.secret.dpapiFileRemoved -and -not (Test-Path $dpapiFile)) "secret retired after a live certificate proof"
    Assert-True ($null -eq $SecretPath -and -not $HasSecretCredential) "in-memory fallback cleared"
    Assert-True ($ret.certificate.wasInStore -and $null -eq (Get-ChildItem "Cert:\CurrentUser\My\$($cert.Thumbprint)" -ErrorAction SilentlyContinue)) "old certificate removed from the store"
    Assert-True (((Read-CredentialState).retiredThumbprints) -contains $cert.Thumbprint) "state records the retired thumbprint"
    [void]$script:CreatedCerts.Remove($cert.Thumbprint)

    # ============================================================ T8: telemetry / capabilities payload
    Section "T8 telemetry is JSON-safe and carries no secret"
    $Secret = "mock-secret-value"; $HasSecretCredential = $true
    $tele = Get-CredentialTelemetry
    $json = $tele | ConvertTo-Json -Depth 6 -Compress
    Assert-True ($json.Length -gt 50 -and -not $json.Contains("mock-secret-value")) "capabilities credential block serialises without the secret value"
    Assert-True ($tele.plaintextSecretPresent -eq $true -and $tele.secretConfigured -eq "plaintext") "plaintext secret is FLAGGED in telemetry"
    Assert-True ($tele.activeCertificate.found -and $tele.activeCertificate.daysToExpiry -ge 44 -and $tele.activeCertificate.daysToExpiry -le 45) "active certificate expiry surfaced (daysToExpiry=$($tele.activeCertificate.daysToExpiry))"
    $status = Invoke-CredentialRotate ([pscustomobject]@{ action = "status" })
    Assert-True ($status.ok -and (@($status.certificates | Where-Object { $_.thumbprint -eq $enroll.thumbprint })).Count -eq 1) "status lists the bay certificate"
    Assert-Throws { Invoke-CredentialRotate ([pscustomobject]@{ action = "bogus" }) } "unknown action" "unknown action is rejected"

    # ============================================================ T9: startup rules
    Section "T9 startup fail-fast: missing DPAPI file is fatal only when the secret is the ONLY credential"
    $missing = Join-Path $BaseDir "secrets\gone.dpapi"
    $Secret = $null; $SecretPath = $missing; $SecretPathCfg = $missing; $HasSecretCredential = $true
    $script:LogLines.Clear()
    Write-CredentialStartupSummary
    Assert-True ($null -eq $SecretPath -and -not $HasSecretCredential) "with a certificate active: missing DPAPI file downgraded to certificate-only"
    Assert-True ((($script:LogLines | Where-Object { $_ -match "^\[WARN\].*file is missing" }) | Measure-Object).Count -eq 1) "...and logged at WARN"
    Assert-True ((($script:LogLines | Where-Object { $_ -match "^\[INFO\] Auth mode: CERTIFICATE" }) | Measure-Object).Count -eq 1) "startup names the certificate mode"
    Remove-Item -LiteralPath $CredentialStatePath -Force
    $SecretPath = $missing; $SecretPathCfg = $missing; $HasSecretCredential = $true
    Assert-Throws { Write-CredentialStartupSummary } "file not found" "with NO certificate: missing DPAPI file is fatal (original behaviour)"

    # ============================================================ T10: -EnrollCert semantics on a bay with no credential
    Section "T10 enroll on a bay with NO credential at all activates directly (Day-0)"
    $Secret = $null; $SecretPath = $null; $SecretPathCfg = $null; $HasSecretCredential = $false; $CertThumbprintCfg = $null
    $day0 = Invoke-CredentialEnroll @{ validityDays = 40; force = $true; subject = "CN=ABG-BayAgent credtest3 $BayId" }
    [void]$script:CreatedCerts.Add($day0.thumbprint)
    Assert-True ($day0.activatedDirectly -and (Get-ActiveCertThumbprint) -eq $day0.thumbprint) "no prior credential: enrolled certificate becomes active immediately"

    # ============================================================ T12 the enroll result must survive build_resultjson
    Section "T12 command results always fit build_resultjson (Memo, MaxLength 2000)"

    # Small results are passed through byte-for-byte - the guard must not disturb the normal path.
    $small = [ordered]@{ ok = $true; action = "status"; note = "tiny" }
    $smallJson = Limit-ResultJson -ResultObj $small
    Assert-True ($smallJson -eq ($small | ConvertTo-Json -Depth 10 -Compress)) "a small result is unchanged by the guard"
    Assert-True ($smallJson -notmatch "resultTrimmed") "a small result is not marked trimmed"

    # A REAL enroll result at the default key length must fit with room to spare.
    $sizeCert = New-BayClientCertificate -Subject "CN=ABG-BayAgent 44d35503-6d63-f011-bec2-0022480b527b" -ValidityDays 730 -Store "CurrentUser" -KeyLength 2048
    [void]$script:CreatedCerts.Add($sizeCert.Thumbprint)
    $enrollRes = Build-CredentialEnrollResult -cert $sizeCert -cerPath "C:\AllBirdies\BayAgent\state\bay-cert-$($sizeCert.Thumbprint).cer" -reused $false -activatedDirectly $false
    $rawLen = (($enrollRes | ConvertTo-Json -Depth 10 -Compress)).Length
    $enrollJson = Limit-ResultJson -ResultObj $enrollRes
    Write-Host ("  enroll result RSA2048: raw={0} chars, stored={1} chars, cap={2}" -f $rawLen, $enrollJson.Length, $ResultJsonMaxChars)
    Assert-True ($rawLen -le $ResultJsonMaxChars) "RSA2048 enroll result fits build_resultjson untrimmed ($rawLen chars)"
    Assert-True ($enrollJson -eq ($enrollRes | ConvertTo-Json -Depth 10 -Compress)) "...so the guard leaves it alone"
    $back = $enrollJson | ConvertFrom-Json
    Assert-True ($back.publicCertBase64 -eq [Convert]::ToBase64String($sizeCert.RawData)) "the public certificate survives the round trip intact"

    # 4096 is refused up front, and the refusal says WHY (this is the regression that matters: without the
    # message the next person just widens the allow-list and reintroduces a result that cannot be returned).
    Assert-Throws { New-BayClientCertificate -Subject "CN=ABG-BayAgent test" -KeyLength 4096 } "build_resultjson" `
        "keyLength 4096 is refused because its public cert cannot be returned in build_resultjson"
    Assert-Throws { New-BayClientCertificate -Subject ("CN=" + ("x" * 200)) -KeyLength 2048 } "120 characters" `
        "an over-long subject is refused before it can eat the result budget"

    # An over-cap result is TRIMMED, never dropped and never silently mangled: the key material and the
    # identity survive, and the result says what was removed.
    $fat = [ordered]@{
        ok = $true; action = "enroll"; reused = $false; activatedDirectly = $false
        thumbprint = $sizeCert.Thumbprint
        subject = $sizeCert.Subject; store = "CurrentUser\My"
        notBeforeUtc = "2026-08-29T00:00:00Z"; notAfterUtc = "2028-08-28T00:00:00Z"
        publicCertBase64 = [Convert]::ToBase64String($sizeCert.RawData)
        publicCertPath = "C:\AllBirdies\BayAgent\state\bay-cert-x.cer"
        next = ("N" * 600)
    }
    $fatRaw = (($fat | ConvertTo-Json -Depth 10 -Compress)).Length
    $fatJson = Limit-ResultJson -ResultObj $fat
    $fatBack = $fatJson | ConvertFrom-Json
    Assert-True ($fatRaw -gt $ResultJsonMaxChars) "the oversized fixture really is over the cap ($fatRaw chars)"
    Assert-True ($fatJson.Length -le $ResultJsonMaxChars) "trimmed result fits the column ($($fatJson.Length) chars)"
    Assert-True ($fatBack.publicCertBase64 -eq [Convert]::ToBase64String($sizeCert.RawData)) "the public certificate is preserved while prose is dropped"
    Assert-True ($fatBack.thumbprint -eq $sizeCert.Thumbprint) "the thumbprint is preserved"
    Assert-True ($fatBack.resultTrimmed -eq $true) "the result is FLAGGED as trimmed (a reader cannot mistake it for complete)"
    Assert-True ($fatBack.resultDroppedKeys -match "next") "the dropped keys are named"

    # A result that cannot fit even after pruning says so instead of shipping a half certificate.
    $huge = [ordered]@{ ok = $true; action = "enroll"; thumbprint = $sizeCert.Thumbprint; publicCertBase64 = ("A" * 2500) }
    $hugeBack = (Limit-ResultJson -ResultObj $huge) | ConvertFrom-Json
    Assert-True ($null -eq $hugeBack.publicCertBase64) "an unfittable certificate is nulled, not half-written"
    Assert-True ([string]$hugeBack.publicCertBase64Omitted -match "bay-cert") "...and the result points at the on-disk copy"

    # Strings (the legacy result shape) are truncated, not passed through over-length.
    $strOut = Limit-ResultJson -ResultObj ("z" * 5000)
    Assert-True ($strOut.Length -le $ResultJsonMaxChars) "an over-long string result is truncated to the cap"
    Assert-True ($strOut.EndsWith("...[truncated]")) "...and marked as truncated"

    # ============================================================ T11 (opt-in): the real Entra endpoint parses the assertion
    if ($Live) {
        Section "T11 LIVE: real Entra rejects an assertion from the UNREGISTERED test key with AADSTS700027 (no write)"
        $TokenAuthorityHost = "https://login.microsoftonline.com"
        $TenantId = $LiveTenantId; $ClientId = $LiveClientId; $OrgUrl = $LiveOrgUrl
        $liveCert = Find-ClientCertificate $day0.thumbprint
        $threw = $false; $msg = ""; $bodyLine = ""
        $script:LogLines.Clear()
        try { $null = Acquire-TokenWithCertificate -Thumbprint $liveCert.Thumbprint } catch { $threw = $true; $msg = $_.Exception.Message }
        $bodyLine = ($script:LogLines | Where-Object { $_ -match "Token failed" } | Select-Object -First 1)
        Write-Host "  entra said: $bodyLine"
        Assert-True ($threw -and $msg -match "HTTP 401") "home tenant: request rejected with HTTP 401 (threw: $msg)"
        Assert-True ($msg -match "AADSTS700027") "home tenant: AADSTS700027 = assertion parsed, thumbprint looked up, key not registered (NOT a malformed-assertion error)"
        Assert-True ($bodyLine -match [regex]::Escape($liveCert.Thumbprint)) "Entra echoes the thumbprint it looked up = our x5t was read correctly"
        # Informational: the single-tenant app is invisible to a customer tenant (census cell 1, now with a certificate).
        $TenantId = $LiveForeignTenantId
        $script:LogLines.Clear(); $msg2 = ""
        try { $null = Acquire-TokenWithCertificate -Thumbprint $liveCert.Thumbprint } catch { $msg2 = $_.Exception.Message }
        Write-Host "  INFO foreign tenant $LiveForeignTenantId answered: $msg2  (expect AADSTS700016 until the app is multi-tenant + consented)"
        $TenantId = $LiveTenantId
    } else {
        Write-Host ""; Write-Host "T11 LIVE Entra probe skipped (pass -Live to run it; it makes no Azure write)" -ForegroundColor Yellow
    }
}
finally {
    $sync["Stop"] = $true
    try { $mock.PS.Stop() } catch {}
    try { $mock.RS.Close() } catch {}
    foreach ($tp in @($script:CreatedCerts)) {
        try { Remove-Item -LiteralPath "Cert:\CurrentUser\My\$tp" -DeleteKey -Force -ErrorAction SilentlyContinue } catch {}
    }
    try { Remove-Item -LiteralPath $BaseDir -Recurse -Force -ErrorAction SilentlyContinue } catch {}
}

Write-Host ""
if ($sync["Errors"].Count -gt 0) { Write-Host "mock endpoint errors: $($sync['Errors'] -join ' | ')" -ForegroundColor Yellow }
Write-Host ("RESULT: {0} passed, {1} failed" -f $script:Pass, $script:Fail) -ForegroundColor $(if ($script:Fail -eq 0) { "Green" } else { "Red" })
if ($script:Fail -gt 0) { $script:Failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }; exit 1 }
exit 0
