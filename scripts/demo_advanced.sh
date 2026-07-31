#!/usr/bin/env bash
# Script demo 5 trường hợp nâng cao để lấy ảnh minh chứng
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Sửa lỗi jq command not found trên Windows Bash
jq() {
    ./.venv/Scripts/jq.exe "$@"
}

DB_FILE="data/_demo_advanced.db"
PORT=8200
BASE="http://localhost:$PORT"

echo "Đang dọn dẹp và khởi động server ảo trên port $PORT..."
rm -f "$DB_FILE"
DATABASE_URL="sqlite:///./$DB_FILE" .venv/Scripts/uvicorn.exe app.main:app --port "$PORT" > /tmp/mv-adv.log 2>&1 &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true; rm -f "$DB_FILE"' EXIT

for _ in $(seq 1 30); do
    curl -s "$BASE/health" > /dev/null 2>&1 && break
    sleep 0.5
done

section() { printf '\n\033[1;36m=== %s ===\033[0m\n' "$1"; }

# 1. SETUP BAN ĐẦU
curl -s -X POST "$BASE/api/v1/vault/init" -H "Content-Type: application/json" -d '{"master_passphrase":"Pass-2026!","confirm_master_passphrase":"Pass-2026!"}' > /dev/null
curl -s -X POST "$BASE/api/v1/vault/unlock" -H "Content-Type: application/json" -d '{"master_passphrase":"Pass-2026!"}' > /dev/null
curl -s -X POST "$BASE/api/v1/auth/register" -H "Content-Type: application/json" -d '{"email":"alice@example.com","passphrase":"Pass-123!","confirm_passphrase":"Pass-123!"}' > /dev/null
curl -s -X POST "$BASE/api/v1/auth/register" -H "Content-Type: application/json" -d '{"email":"bob@example.com","passphrase":"Pass-456!","confirm_passphrase":"Pass-456!"}' > /dev/null

ALICE_TOKEN=$(curl -s -X POST "$BASE/api/v1/auth/login" -H "Content-Type: application/json" -d '{"email":"alice@example.com","passphrase":"Pass-123!"}' | jq -r .data.access_token)
BOB_TOKEN=$(curl -s -X POST "$BASE/api/v1/auth/login" -H "Content-Type: application/json" -d '{"email":"bob@example.com","passphrase":"Pass-456!"}' | jq -r .data.access_token)

# 2. CÁC TRƯỜNG HỢP MỚI
section "Ảnh 3.4.2: Ghi nhận truy cập trái phép vào Audit Log (Lỗi 403)"
curl -s -X PUT "$BASE/api/v1/kv/secret/alice@example.com/test" -H "Authorization: Bearer $ALICE_TOKEN" -H "Content-Type: application/json" -d '{"data":{"secret":"123"}}' > /dev/null
echo "> Bob cố đọc secret của Alice:"
curl -s "$BASE/api/v1/kv/secret/alice@example.com/test" -H "Authorization: Bearer $BOB_TOKEN" | jq .
echo "> Kiểm tra dòng Audit Log vừa sinh ra dưới DB:"
sqlite3 "$DB_FILE" "SELECT timestamp, action, actor_email, target_path, status FROM audit_logs WHERE status='DENIED';"

section "Ảnh 3.3.2: Tamper-evident, can thiệp CSDL -> DECRYPTION_FAILED"
python3 - "$DB_FILE" <<'EOF'
import sqlite3, sys
con = sqlite3.connect(sys.argv[1])
ct = con.execute("SELECT ciphertext_b64 FROM kv_secrets WHERE path='secret/alice@example.com/test'").fetchone()[0]
tampered = ct[:-1] + ("A" if ct[-1] != "A" else "B")
con.execute("UPDATE kv_secrets SET ciphertext_b64=? WHERE path='secret/alice@example.com/test'", (tampered,))
con.commit()
EOF
echo "> Dữ liệu đã bị sửa, Alice tiến hành đọc lại:"
curl -s "$BASE/api/v1/kv/secret/alice@example.com/test" -H "Authorization: Bearer $ALICE_TOKEN" | jq .

section "Ảnh 3.6.2: Invalid Key Usage (Dùng khóa ký số để Encrypt)"
curl -s -X POST "$BASE/api/v1/transit/signing-keys" -H "Authorization: Bearer $ALICE_TOKEN" -H "Content-Type: application/json" -d '{"key_name":"my-sign-key","signing_algorithm":"ED25519"}' > /dev/null
echo "> Cố dùng my-sign-key để mã hóa dữ liệu:"
curl -s -X POST "$BASE/api/v1/transit/encrypt" -H "Authorization: Bearer $ALICE_TOKEN" -H "Content-Type: application/json" -d '{"key_name":"my-sign-key","plaintext_b64":"SGVsbG8="}' | jq .

section "Ảnh 3.5.2: Vô hiệu hóa khóa và lỗi KEY_NOT_FOUND"
curl -s -X POST "$BASE/api/v1/transit/keys" -H "Authorization: Bearer $ALICE_TOKEN" -H "Content-Type: application/json" -d '{"key_name":"my-aes-key","key_usage":"ENCRYPT_DECRYPT"}' > /dev/null
echo "> Tiến hành Revoke khóa:"
curl -s -X POST "$BASE/api/v1/transit/keys/my-aes-key/revoke" -H "Authorization: Bearer $ALICE_TOKEN" | jq .
echo "> Thử Encrypt bằng khóa đã revoke:"
curl -s -X POST "$BASE/api/v1/transit/encrypt" -H "Authorization: Bearer $ALICE_TOKEN" -H "Content-Type: application/json" -d '{"key_name":"my-aes-key","plaintext_b64":"SGVsbG8="}' | jq .

section "Ảnh 3.8.3: Bắt lỗi INVALID_DIGEST_LENGTH (Ký số SHA256 bị thiếu byte)"
echo "> Truyền message_type=DIGEST nhưng payload chỉ có vài byte (thay vì 32 bytes):"
curl -s -X POST "$BASE/api/v1/transit/sign" -H "Authorization: Bearer $ALICE_TOKEN" -H "Content-Type: application/json" -d '{"key_name":"my-sign-key","message_b64":"c2hvcnQ=","message_type":"DIGEST"}' | jq .

echo -e "\nHoàn tất demo các tính năng nâng cao!"
