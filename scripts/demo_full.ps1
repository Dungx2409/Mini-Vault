# demo_full.ps1 - Kich ban demo toan bo 8 tinh nang bat buoc (Windows PowerShell)
# Chay: .venv\Scripts\activate roi .\scripts\demo_full.ps1

$ErrorActionPreference = "Continue"

$PORT = 8199
$BASE = "http://127.0.0.1:$PORT"
$DB_FILE = "data\_demo_run.db"

# Xoa DB cu neu co
if (Test-Path $DB_FILE) { Remove-Item $DB_FILE -Force }

# Khoi dong server nen
Write-Host "`n[*] Khoi dong server tren port $PORT..." -ForegroundColor Yellow
$env:DATABASE_URL = "sqlite:///./data/_demo_run.db"
$server = Start-Process -FilePath ".venv\Scripts\uvicorn.exe" -ArgumentList "app.main:app","--port",$PORT -PassThru -WindowStyle Hidden

# Cho server san sang
Write-Host "[*] Cho server khoi dong..." -ForegroundColor Yellow
for ($i = 0; $i -lt 30; $i++) {
    try {
        $null = Invoke-RestMethod -Uri "$BASE/health" -Method Get -TimeoutSec 1
        Write-Host "[OK] Server da san sang!`n" -ForegroundColor Green
        break
    } catch {
        Start-Sleep -Milliseconds 500
    }
}

function Section($title) {
    Write-Host ""
    Write-Host "=== $title ===" -ForegroundColor Cyan
}

function Api {
    param([string]$method, [string]$uri, [string]$body = "", [string]$token = "")
    Write-Host "> $method $uri" -ForegroundColor Gray
    $headers = @{}
    $headers["Content-Type"] = "application/json"
    if ($token -ne "") { $headers["Authorization"] = "Bearer $token" }
    try {
        if ($body -ne "") {
            $resp = Invoke-WebRequest -Uri "$BASE$uri" -Method $method -Body ([System.Text.Encoding]::UTF8.GetBytes($body)) -Headers $headers -UseBasicParsing
        } else {
            $resp = Invoke-WebRequest -Uri "$BASE$uri" -Method $method -Headers $headers -UseBasicParsing
        }
        $resp.Content | ConvertFrom-Json | ConvertTo-Json -Depth 10
    } catch {
        if ($_.ErrorDetails.Message) {
            try {
                $_.ErrorDetails.Message | ConvertFrom-Json | ConvertTo-Json -Depth 10
            } catch {
                Write-Host $_.ErrorDetails.Message -ForegroundColor Red
            }
        } else {
            Write-Host "Loi: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

try {
    # ======================== FEATURE 0.1 ========================
    Section "0.1 - Vault status truoc khi init (locked - chua initialized)"
    Api "GET" "/api/v1/vault/status"

    Section "0.1 - Goi API can token khi vault chua init (UNAUTHENTICATED)"
    Api "GET" "/api/v1/kv"

    Section "0.1 - Khoi tao vault (init)"
    Api "POST" "/api/v1/vault/init" '{"master_passphrase":"Strong-Master-Passphrase-2026!","confirm_master_passphrase":"Strong-Master-Passphrase-2026!"}'

    Section "0.1 - Unlock SAI master passphrase"
    Api "POST" "/api/v1/vault/unlock" '{"master_passphrase":"wrong-passphrase"}'

    Section "0.1 - Unlock DUNG master passphrase"
    Api "POST" "/api/v1/vault/unlock" '{"master_passphrase":"Strong-Master-Passphrase-2026!"}'

    # ======================== FEATURE 0.2 ========================
    Section "0.2 - Dang ky Alice - Bob va locktest"
    Api "POST" "/api/v1/auth/register" '{"email":"alice@example.com","passphrase":"StrongPassword@123","confirm_passphrase":"StrongPassword@123"}'
    Api "POST" "/api/v1/auth/register" '{"email":"bob@example.com","passphrase":"StrongPassword@456","confirm_passphrase":"StrongPassword@456"}'
    Api "POST" "/api/v1/auth/register" '{"email":"locktest@example.com","passphrase":"StrongPassword@000","confirm_passphrase":"StrongPassword@000"}'

    Section "0.2 - Dang ky trung email (EMAIL_ALREADY_EXISTS)"
    Api "POST" "/api/v1/auth/register" '{"email":"alice@example.com","passphrase":"StrongPassword@123","confirm_passphrase":"StrongPassword@123"}'

    Section "0.2 - Dang ky mat khau yeu (WEAK_PASSPHRASE)"
    Api "POST" "/api/v1/auth/register" '{"email":"weak@example.com","passphrase":"123456","confirm_passphrase":"123456"}'

    Section "0.2 - Sai passphrase 5 lan -> ACCOUNT_LOCKED"
    for ($i = 1; $i -le 5; $i++) {
        Write-Host "> Login locktest - lan sai thu $i" -ForegroundColor Gray
        Api "POST" "/api/v1/auth/login" '{"email":"locktest@example.com","passphrase":"WrongPass@000"}'
    }
    Write-Host "> Login locktest voi MAT KHAU DUNG trong khi bi khoa:" -ForegroundColor Gray
    Api "POST" "/api/v1/auth/login" '{"email":"locktest@example.com","passphrase":"StrongPassword@000"}'

    Section "0.2 - Login Alice va Bob (lay session token)"
    $aliceResp = Invoke-RestMethod -Uri "$BASE/api/v1/auth/login" -Method POST -Body '{"email":"alice@example.com","passphrase":"StrongPassword@123"}' -ContentType "application/json"
    $aliceResp | ConvertTo-Json -Depth 10
    $ALICE_TOKEN = $aliceResp.data.access_token

    $bobResp = Invoke-RestMethod -Uri "$BASE/api/v1/auth/login" -Method POST -Body '{"email":"bob@example.com","passphrase":"StrongPassword@456"}' -ContentType "application/json"
    $bobResp | ConvertTo-Json -Depth 10
    $BOB_TOKEN = $bobResp.data.access_token

    Write-Host ""
    Write-Host "[INFO] ALICE_TOKEN = $($ALICE_TOKEN.Substring(0,20))..." -ForegroundColor DarkGray
    Write-Host "[INFO] BOB_TOKEN   = $($BOB_TOKEN.Substring(0,20))..." -ForegroundColor DarkGray

    # ======================== FEATURE 1.1 ========================
    Section "1.1 - Alice ghi secret (write)"
    Api "PUT" "/api/v1/kv/secret/alice@example.com/database" '{"data":{"username":"admin","password":"database-password","host":"localhost"}}' $ALICE_TOKEN

    Section "1.1 - Alice doc lai secret (round-trip)"
    Api "GET" "/api/v1/kv/secret/alice@example.com/database" "" $ALICE_TOKEN

    # ======================== FEATURE 1.2 ========================
    Section "1.2 - Bob doc secret cua Alice -> PERMISSION_DENIED"
    Api "GET" "/api/v1/kv/secret/alice@example.com/database" "" $BOB_TOKEN

    Section "1.2 - Request KV khong co token -> UNAUTHENTICATED"
    Api "GET" "/api/v1/kv/secret/alice@example.com/database"

    # ======================== FEATURE 2.1 ========================
    Section "2.1 - Alice tao named AES key payment-key"
    Api "POST" "/api/v1/transit/keys" '{"key_name":"payment-key","key_usage":"ENCRYPT_DECRYPT"}' $ALICE_TOKEN

    Section "2.1 - Tao trung ten key -> KEY_ALREADY_EXISTS"
    Api "POST" "/api/v1/transit/keys" '{"key_name":"payment-key","key_usage":"ENCRYPT_DECRYPT"}' $ALICE_TOKEN

    Section "2.1 - list_keys KHONG BAO GIO lo key material"
    Api "GET" "/api/v1/transit/keys" "" $ALICE_TOKEN

    # ======================== FEATURE 2.2 ========================
    Section "2.2 - Alice encrypt bang payment-key"
    $encHeaders = @{}
    $encHeaders["Content-Type"] = "application/json"
    $encHeaders["Authorization"] = "Bearer $ALICE_TOKEN"
    $encResp = Invoke-WebRequest -Uri "$BASE/api/v1/transit/encrypt" -Method POST -Body '{"key_name":"payment-key","plaintext_b64":"SGVsbG8gTWluaSBWYXVsdA=="}' -Headers $encHeaders -UseBasicParsing
    $encObj = $encResp.Content | ConvertFrom-Json
    $encObj | ConvertTo-Json -Depth 10
    $CIPHERTEXT = $encObj.data.ciphertext

    Section "2.2 - Alice decrypt lai (round-trip)"
    $decBody = '{"ciphertext":"' + $CIPHERTEXT + '"}'
    Api "POST" "/api/v1/transit/decrypt" $decBody $ALICE_TOKEN

    Section "2.2 - Tao signing key roi dung SAI loai de encrypt -> INVALID_KEY_USAGE"
    Api "POST" "/api/v1/transit/signing-keys" '{"key_name":"document-signing-key","signing_algorithm":"ED25519"}' $ALICE_TOKEN
    Api "POST" "/api/v1/transit/encrypt" '{"key_name":"document-signing-key","plaintext_b64":"SGVsbG8="}' $ALICE_TOKEN

    # ======================== FEATURE 2.3 ========================
    Section "2.3 - Bob dung key cua Alice de encrypt -> PERMISSION_DENIED"
    Api "POST" "/api/v1/transit/encrypt" '{"key_name":"payment-key","plaintext_b64":"SGVsbG8="}' $BOB_TOKEN

    # ======================== FEATURE 2.4 ========================
    Section "2.4 - Alice ky (sign) mot message"
    $signHeaders = @{}
    $signHeaders["Content-Type"] = "application/json"
    $signHeaders["Authorization"] = "Bearer $ALICE_TOKEN"
    $signResp = Invoke-WebRequest -Uri "$BASE/api/v1/transit/sign" -Method POST -Body '{"key_name":"document-signing-key","message_b64":"SGVsbG8gTWluaSBWYXVsdA==","message_type":"RAW"}' -Headers $signHeaders -UseBasicParsing
    $signObj = $signResp.Content | ConvertFrom-Json
    $signObj | ConvertTo-Json -Depth 10
    $SIG = $signObj.data.signature_b64

    Section "2.4 - Verify message GOC -> signature_valid: true"
    $verifyBody = '{"key_name":"document-signing-key","message_b64":"SGVsbG8gTWluaSBWYXVsdA==","message_type":"RAW","signature_b64":"' + $SIG + '"}'
    Api "POST" "/api/v1/transit/verify" $verifyBody $ALICE_TOKEN

    Section "2.4 - Verify message DA SUA 1 byte -> signature_valid: false"
    $verifyBadBody = '{"key_name":"document-signing-key","message_b64":"SGVsbG8gTWluaSBWYXVsdD8=","message_type":"RAW","signature_b64":"' + $SIG + '"}'
    Api "POST" "/api/v1/transit/verify" $verifyBadBody $ALICE_TOKEN

    # ======================== LOCK ========================
    Section "0.1 - Lock vault"
    Api "POST" "/api/v1/vault/lock"
    Api "GET" "/api/v1/kv/secret/alice@example.com/database" "" $ALICE_TOKEN

    Section "HOAN TAT"
    Write-Host "Toan bo 8 muc bat buoc (0.1 - 0.2 - 1.1 - 1.2 - 2.1 - 2.2 - 2.3 - 2.4) da chay xong." -ForegroundColor Green
}
finally {
    Write-Host ""
    Write-Host "[*] Tat server va don dep..." -ForegroundColor Yellow
    if ($server -and !$server.HasExited) { Stop-Process -Id $server.Id -Force }
    if (Test-Path $DB_FILE) { Remove-Item $DB_FILE -Force }
    $env:DATABASE_URL = $null
    Write-Host "[OK] Da don dep xong." -ForegroundColor Green
}
