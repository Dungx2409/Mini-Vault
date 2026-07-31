# demo_advanced.ps1 - Kich ban demo 3 Tinh Nang Nang Cao (Windows PowerShell)
# Chay: .venv\Scripts\activate roi .\scripts\demo_advanced.ps1

$ErrorActionPreference = "Continue"

$PORT = 8200
$BASE = "http://127.0.0.1:$PORT"
$DB_FILE = "data\_demo_advanced.db"

# Xoa DB cu neu co
if (Test-Path $DB_FILE) { Remove-Item $DB_FILE -Force }

# Khoi dong server nen
Write-Host "`n[*] Khoi dong server ao tren port $PORT..." -ForegroundColor Yellow
$env:DATABASE_URL = "sqlite:///./data/_demo_advanced.db"
$server = Start-Process -FilePath ".venv\Scripts\uvicorn.exe" -ArgumentList "app.main:app","--port",$PORT -PassThru -WindowStyle Hidden

# Cho server san sang
Write-Host "[*] Cho server khoi dong..." -ForegroundColor Yellow
for ($i = 0; $i -lt 30; $i++) {
    try {
        $null = Invoke-RestMethod -Uri "$BASE/health" -Method Get -TimeoutSec 1
        break
    } catch {
        Start-Sleep -Milliseconds 500
    }
}

function Section($title) {
    Write-Host "`n=== $title ===" -ForegroundColor Cyan
}

function Api {
    param([string]$method, [string]$uri, [string]$body = "", [string]$token = "")
    Write-Host "> $method $uri" -ForegroundColor Gray
    $headers = @{ "Content-Type" = "application/json" }
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
    # 1. SETUP BAN DAU
    $null = Invoke-RestMethod -Uri "$BASE/api/v1/vault/init" -Method POST -Body '{"master_passphrase":"Strong-Master-Passphrase-2026!","confirm_master_passphrase":"Strong-Master-Passphrase-2026!"}' -ContentType "application/json"
    $null = Invoke-RestMethod -Uri "$BASE/api/v1/vault/unlock" -Method POST -Body '{"master_passphrase":"Strong-Master-Passphrase-2026!"}' -ContentType "application/json"
    $null = Invoke-RestMethod -Uri "$BASE/api/v1/auth/register" -Method POST -Body '{"email":"alice@example.com","passphrase":"StrongPassword@123","confirm_passphrase":"StrongPassword@123"}' -ContentType "application/json"
    $null = Invoke-RestMethod -Uri "$BASE/api/v1/auth/register" -Method POST -Body '{"email":"bob@example.com","passphrase":"StrongPassword@456","confirm_passphrase":"StrongPassword@456"}' -ContentType "application/json"
    
    $ALICE_TOKEN = (Invoke-RestMethod -Uri "$BASE/api/v1/auth/login" -Method POST -Body '{"email":"alice@example.com","passphrase":"StrongPassword@123"}' -ContentType "application/json").data.access_token
    $BOB_TOKEN = (Invoke-RestMethod -Uri "$BASE/api/v1/auth/login" -Method POST -Body '{"email":"bob@example.com","passphrase":"StrongPassword@456"}' -ContentType "application/json").data.access_token

    # ==============================================================
    # 1. NÂNG CAO: SECRET VERSIONING (+0.3 điểm)
    # ==============================================================
    Section "ADVANCED 1: SECRET VERSIONING (Luu nhieu phien ban cua 1 Secret)"
    Api "PUT" "/api/v1/kv/secret/alice@example.com/api-key" '{"data":{"key":"AAAAA"}}' $ALICE_TOKEN
    Api "PUT" "/api/v1/kv/secret/alice@example.com/api-key" '{"data":{"key":"BBBBB"}}' $ALICE_TOKEN
    
    Write-Host "`n> Doc Version 1 (cu):" -ForegroundColor Gray
    Api "GET" "/api/v1/kv/secret/alice@example.com/api-key?version=1" "" $ALICE_TOKEN
    Write-Host "`n> Doc Version 2 (moi):" -ForegroundColor Gray
    Api "GET" "/api/v1/kv/secret/alice@example.com/api-key?version=2" "" $ALICE_TOKEN

    # ==============================================================
    # 2. NÂNG CAO: KEY ROTATION (+0.4 điểm)
    # ==============================================================
    Section "ADVANCED 2: KEY ROTATION (Xoay vong khoa Transit)"
    Api "POST" "/api/v1/transit/keys" '{"key_name":"master-key","key_usage":"ENCRYPT_DECRYPT"}' $ALICE_TOKEN
    
    # Ma hoa bang khoa V1
    $encV1 = Invoke-RestMethod -Uri "$BASE/api/v1/transit/encrypt" -Method POST -Body '{"key_name":"master-key","plaintext_b64":"SGVsbG8gVjE="}' -ContentType "application/json" -Headers @{ "Authorization" = "Bearer $ALICE_TOKEN" }
    $ctV1 = $encV1.data.ciphertext
    Write-Host "> Ma hoa lan 1 (Version 1): $ctV1" -ForegroundColor Green

    # Rotate khoa len V2
    Write-Host "`n> Xoay vong khoa (Rotate) len Version 2:" -ForegroundColor Gray
    Api "POST" "/api/v1/transit/keys/master-key/rotate" "" $ALICE_TOKEN

    # Ma hoa bang khoa V2
    $encV2 = Invoke-RestMethod -Uri "$BASE/api/v1/transit/encrypt" -Method POST -Body '{"key_name":"master-key","plaintext_b64":"SGVsbG8gVjI="}' -ContentType "application/json" -Headers @{ "Authorization" = "Bearer $ALICE_TOKEN" }
    $ctV2 = $encV2.data.ciphertext
    Write-Host "> Ma hoa lan 2 (Version 2): $ctV2" -ForegroundColor Green

    Write-Host "`n> Giai ma lai ciphertext V1 (He thong tu dong nhan dien dung khoa V1 de giai ma):" -ForegroundColor Gray
    $decBody = "{`"ciphertext`":`"$ctV1`"}"
    Api "POST" "/api/v1/transit/decrypt" $decBody $ALICE_TOKEN

    # ==============================================================
    # 3. NÂNG CAO: TAMPER-EVIDENT AUDIT LOG (+0.3 điểm)
    # ==============================================================
    Section "ADVANCED 3: TAMPER-EVIDENT AUDIT LOG (Phat hien sua doi Log)"
    
    # Tao them 1 dong log bi tu choi cho phong phu
    try {
        $null = Invoke-WebRequest -Uri "$BASE/api/v1/kv/secret/alice@example.com/api-key" -Method GET -Headers @{ "Authorization" = "Bearer $BOB_TOKEN" } -UseBasicParsing
    } catch {}

    Write-Host "> Xac minh chuoi log (Truoc khi bi xam pham):" -ForegroundColor Gray
    Api "GET" "/api/v1/audit/verify" "" $ALICE_TOKEN

    Write-Host "`n> [HACKER ATTACK] Dung Python de len sua CSDL (Doi DENIED thanh GRANTED o dong log cuoi cung)..." -ForegroundColor Red
    "import sqlite3`ncon=sqlite3.connect('data/_demo_advanced.db')`ncon.execute(`"UPDATE audit_logs SET result='GRANTED' WHERE result='DENIED'`")`ncon.commit()" | .venv\Scripts\python.exe
    Write-Host "[OK] Hacker da sua CSDL thanh cong." -ForegroundColor Red

    Write-Host "`n> Xac minh lai chuoi log (Sau khi bi xam pham):" -ForegroundColor Gray
    Api "GET" "/api/v1/audit/verify" "" $ALICE_TOKEN

    Section "HOAN TAT DEMO NANG CAO"
    Write-Host "Chuc mung ban da bieu dien xong 3 tinh nang nang cao nhat de lay tron +1.0 diem!" -ForegroundColor Green

}
finally {
    if ($server -and !$server.HasExited) { Stop-Process -Id $server.Id -Force }
    Start-Sleep -Seconds 1  # Cho he dieu hanh Windows nha khoa (release lock) cua file CSDL
    if (Test-Path $DB_FILE) { Remove-Item $DB_FILE -Force }
}
