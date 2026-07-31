#!/usr/bin/env bash
# Runs the entire acceptance-criteria demo (section VI of the assignment) against an isolated
# throwaway database and prints every request/response so the transcript can be pasted into the
# report as screenshots or read aloud while recording the video. Does not touch data/mini_vault.db
# or data/samples/*. Usage: scripts/demo_full.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Sửa lỗi jq command not found trên Windows Bash
jq() {
    ./.venv/Scripts/jq.exe "$@"
}

DB_FILE="data/_demo_run.db"
PORT=8199
BASE="http://localhost:$PORT"

rm -f "$DB_FILE"
DATABASE_URL="sqlite:///./$DB_FILE" .venv/Scripts/uvicorn.exe app.main:app --port "$PORT" \
    > /tmp/mini-vault-demo.log 2>&1 &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true; rm -f "$DB_FILE"' EXIT

for _ in $(seq 1 30); do
    curl -s "$BASE/health" > /dev/null 2>&1 && break
    sleep 0.5
done

section() { printf '\n\033[1;36m=== %s ===\033[0m\n' "$1"; }
req() { echo "> $*"; }

section "0.1 — Vault status truoc khi init (locked, chua initialized)"
req "GET /api/v1/vault/status"
curl -s "$BASE/api/v1/vault/status" | jq .

section "0.1 — Goi API can token khi vault chua init (UNAUTHENTICATED, uu tien hon vault state)"
req "GET /api/v1/kv (khong Authorization header)"
curl -s "$BASE/api/v1/kv" | jq .

section "0.1 — Khoi tao vault (init)"
req 'POST /api/v1/vault/init'
curl -s -X POST "$BASE/api/v1/vault/init" -H "Content-Type: application/json" \
    -d '{"master_passphrase":"Strong-Master-Passphrase-2026!","confirm_master_passphrase":"Strong-Master-Passphrase-2026!"}' | jq .

section "0.1 — Unlock SAI master passphrase (loi chung chung, khong lo chi tiet)"
req 'POST /api/v1/vault/unlock (sai)'
curl -s -X POST "$BASE/api/v1/vault/unlock" -H "Content-Type: application/json" \
    -d '{"master_passphrase":"wrong-passphrase"}' | jq .

section "0.1 — Unlock DUNG master passphrase"
req 'POST /api/v1/vault/unlock (dung)'
curl -s -X POST "$BASE/api/v1/vault/unlock" -H "Content-Type: application/json" \
    -d '{"master_passphrase":"Strong-Master-Passphrase-2026!"}' | jq .

section "0.2 — Dang ky Alice, Bob va mot tai khoan rieng de test khoa tai khoan"
req 'POST /api/v1/auth/register alice'
curl -s -X POST "$BASE/api/v1/auth/register" -H "Content-Type: application/json" \
    -d '{"email":"alice@example.com","passphrase":"StrongPassword@123","confirm_passphrase":"StrongPassword@123"}' | jq .
req 'POST /api/v1/auth/register bob'
curl -s -X POST "$BASE/api/v1/auth/register" -H "Content-Type: application/json" \
    -d '{"email":"bob@example.com","passphrase":"StrongPassword@456","confirm_passphrase":"StrongPassword@456"}' | jq .
req 'POST /api/v1/auth/register locktest (chi de demo khoa tai khoan, khong dung tiep ve sau)'
curl -s -X POST "$BASE/api/v1/auth/register" -H "Content-Type: application/json" \
    -d '{"email":"locktest@example.com","passphrase":"StrongPassword@000","confirm_passphrase":"StrongPassword@000"}' | jq .

section "0.2 — Dang ky trung email (EMAIL_ALREADY_EXISTS)"
req 'POST /api/v1/auth/register alice (lan 2)'
curl -s -X POST "$BASE/api/v1/auth/register" -H "Content-Type: application/json" \
    -d '{"email":"alice@example.com","passphrase":"StrongPassword@123","confirm_passphrase":"StrongPassword@123"}' | jq .

section "0.2 — Dang ky mat khau yeu (WEAK_PASSPHRASE)"
req 'POST /api/v1/auth/register weak@example.com voi passphrase "123456"'
curl -s -X POST "$BASE/api/v1/auth/register" -H "Content-Type: application/json" \
    -d '{"email":"weak@example.com","passphrase":"123456","confirm_passphrase":"123456"}' | jq .

section "0.2 — Sai passphrase 5 lan lien tiep tren locktest -> ACCOUNT_LOCKED"
for i in 1 2 3 4 5; do
    req "POST /api/v1/auth/login locktest, lan sai thu $i"
    curl -s -X POST "$BASE/api/v1/auth/login" -H "Content-Type: application/json" \
        -d '{"email":"locktest@example.com","passphrase":"WrongPass@000"}' | jq -c .
done
req 'POST /api/v1/auth/login locktest voi MAT KHAU DUNG ngay trong luc bi khoa (van phai fail)'
curl -s -X POST "$BASE/api/v1/auth/login" -H "Content-Type: application/json" \
    -d '{"email":"locktest@example.com","passphrase":"StrongPassword@000"}' | jq .
echo "(locktest se tu mo khoa sau 5 phut - khong cho o day; hanh vi nay da co pytest rieng trong tests/test_auth.py)"

section "0.2 — Login Alice va Bob (lay session token)"
ALICE_TOKEN=$(curl -s -X POST "$BASE/api/v1/auth/login" -H "Content-Type: application/json" \
    -d '{"email":"alice@example.com","passphrase":"StrongPassword@123"}' | tee /tmp/mv_alice_login.json | jq -r .data.access_token)
cat /tmp/mv_alice_login.json | jq .
BOB_TOKEN=$(curl -s -X POST "$BASE/api/v1/auth/login" -H "Content-Type: application/json" \
    -d '{"email":"bob@example.com","passphrase":"StrongPassword@456"}' | tee /tmp/mv_bob_login.json | jq -r .data.access_token)
cat /tmp/mv_bob_login.json | jq .

section "1.1 — Alice ghi secret (write) - AES-256-GCM, nonce moi moi lan"
req 'PUT /api/v1/kv/secret/alice@example.com/database'
curl -s -X PUT "$BASE/api/v1/kv/secret/alice@example.com/database" \
    -H "Authorization: Bearer $ALICE_TOKEN" -H "Content-Type: application/json" \
    -d '{"data":{"username":"admin","password":"database-password","host":"localhost"}}' | jq .

section "1.1 — Alice doc lai secret (round-trip dung du lieu goc)"
req 'GET /api/v1/kv/secret/alice@example.com/database'
curl -s "$BASE/api/v1/kv/secret/alice@example.com/database" -H "Authorization: Bearer $ALICE_TOKEN" | jq .

section "1.1 — Kiem chung file DB tren dia KHONG chua plaintext cua secret"
if strings "$DB_FILE" | grep -q "database-password"; then
    echo "CANH BAO: tim thay plaintext trong DB!"
else
    echo "OK: khong tim thay chuoi plaintext 'database-password' trong $DB_FILE"
fi

section "1.1 — Tamper 1 byte ciphertext truc tiep tren dia -> read phai bi tu choi 100%"
python3 - "$DB_FILE" <<'EOF'
import sqlite3, sys
con = sqlite3.connect(sys.argv[1])
row = con.execute(
    "SELECT ciphertext_b64 FROM kv_secrets WHERE path='secret/alice@example.com/database'"
).fetchone()
ct = row[0]
tampered = ct[:-1] + ("A" if ct[-1] != "A" else "B")
con.execute(
    "UPDATE kv_secrets SET ciphertext_b64=? WHERE path='secret/alice@example.com/database'",
    (tampered,),
)
con.commit()
print(f"ciphertext_b64 doi tu ...{ct[-8:]} thanh ...{tampered[-8:]}")
EOF
req 'GET /api/v1/kv/secret/alice@example.com/database (sau khi tamper)'
curl -s "$BASE/api/v1/kv/secret/alice@example.com/database" -H "Authorization: Bearer $ALICE_TOKEN" | jq .

section "1.2 — Bob dung token cua CHINH MINH doc secret cua Alice -> PERMISSION_DENIED"
req 'GET /api/v1/kv/secret/alice@example.com/database (token Bob)'
curl -s "$BASE/api/v1/kv/secret/alice@example.com/database" -H "Authorization: Bearer $BOB_TOKEN" | jq .

section "1.2 — Request KV khong co token -> UNAUTHENTICATED (kiem tra truoc ca ownership)"
req 'GET /api/v1/kv/secret/alice@example.com/database (khong token)'
curl -s "$BASE/api/v1/kv/secret/alice@example.com/database" | jq .

section "2.1 — Alice tao named AES key 'payment-key'"
req 'POST /api/v1/transit/keys'
curl -s -X POST "$BASE/api/v1/transit/keys" -H "Authorization: Bearer $ALICE_TOKEN" -H "Content-Type: application/json" \
    -d '{"key_name":"payment-key","key_usage":"ENCRYPT_DECRYPT"}' | jq .

section "2.1 — Tao trung ten key -> KEY_ALREADY_EXISTS"
req 'POST /api/v1/transit/keys (trung ten)'
curl -s -X POST "$BASE/api/v1/transit/keys" -H "Authorization: Bearer $ALICE_TOKEN" -H "Content-Type: application/json" \
    -d '{"key_name":"payment-key","key_usage":"ENCRYPT_DECRYPT"}' | jq .

section "2.1 — list_keys KHONG BAO GIO lo key material"
req 'GET /api/v1/transit/keys'
curl -s "$BASE/api/v1/transit/keys" -H "Authorization: Bearer $ALICE_TOKEN" | jq .

section "2.2 — Alice encrypt bang payment-key"
req 'POST /api/v1/transit/encrypt'
ENC=$(curl -s -X POST "$BASE/api/v1/transit/encrypt" -H "Authorization: Bearer $ALICE_TOKEN" -H "Content-Type: application/json" \
    -d '{"key_name":"payment-key","plaintext_b64":"SGVsbG8gTWluaSBWYXVsdA=="}')
echo "$ENC" | jq .
CIPHERTEXT=$(echo "$ENC" | jq -r .data.ciphertext)

section "2.2 — Alice decrypt lai (round-trip dung plaintext goc)"
req 'POST /api/v1/transit/decrypt'
curl -s -X POST "$BASE/api/v1/transit/decrypt" -H "Authorization: Bearer $ALICE_TOKEN" -H "Content-Type: application/json" \
    -d "{\"ciphertext\":\"$CIPHERTEXT\"}" | jq .

section "2.2 — Tamper 1 ky tu ciphertext transit -> decrypt phai bi tu choi 100%"
TAMPERED_CT="${CIPHERTEXT%?}$([ "${CIPHERTEXT: -1}" != "A" ] && echo A || echo B)"
req 'POST /api/v1/transit/decrypt (ciphertext bi sua)'
curl -s -X POST "$BASE/api/v1/transit/decrypt" -H "Authorization: Bearer $ALICE_TOKEN" -H "Content-Type: application/json" \
    -d "{\"ciphertext\":\"$TAMPERED_CT\"}" | jq .

section "2.2 — Tao signing key roi dung SAI loai (SIGN_VERIFY) de encrypt -> INVALID_KEY_USAGE"
curl -s -X POST "$BASE/api/v1/transit/signing-keys" -H "Authorization: Bearer $ALICE_TOKEN" -H "Content-Type: application/json" \
    -d '{"key_name":"document-signing-key","signing_algorithm":"ED25519"}' | jq .
req 'POST /api/v1/transit/encrypt voi key_name=document-signing-key'
curl -s -X POST "$BASE/api/v1/transit/encrypt" -H "Authorization: Bearer $ALICE_TOKEN" -H "Content-Type: application/json" \
    -d '{"key_name":"document-signing-key","plaintext_b64":"SGVsbG8="}' | jq .

section "2.3 — Bob dung key_name 'payment-key' cua Alice de encrypt -> PERMISSION_DENIED"
req 'POST /api/v1/transit/encrypt (token Bob, key cua Alice)'
curl -s -X POST "$BASE/api/v1/transit/encrypt" -H "Authorization: Bearer $BOB_TOKEN" -H "Content-Type: application/json" \
    -d '{"key_name":"payment-key","plaintext_b64":"SGVsbG8="}' | jq .

section "2.4 — Alice ky (sign) mot message"
SIGN=$(curl -s -X POST "$BASE/api/v1/transit/sign" -H "Authorization: Bearer $ALICE_TOKEN" -H "Content-Type: application/json" \
    -d '{"key_name":"document-signing-key","message_b64":"SGVsbG8gTWluaSBWYXVsdA==","message_type":"RAW"}')
echo "$SIGN" | jq .
SIG=$(echo "$SIGN" | jq -r .data.signature_b64)

section "2.4 — Verify message GOC -> signature_valid: true"
req 'POST /api/v1/transit/verify (message goc)'
curl -s -X POST "$BASE/api/v1/transit/verify" -H "Authorization: Bearer $ALICE_TOKEN" -H "Content-Type: application/json" \
    -d "{\"key_name\":\"document-signing-key\",\"message_b64\":\"SGVsbG8gTWluaSBWYXVsdA==\",\"message_type\":\"RAW\",\"signature_b64\":\"$SIG\"}" | jq .

section "2.4 — Verify message DA SUA 1 byte -> signature_valid: false (khong duoc throw exception)"
req 'POST /api/v1/transit/verify (message bi sua, van cung chu ky)'
curl -s -X POST "$BASE/api/v1/transit/verify" -H "Authorization: Bearer $ALICE_TOKEN" -H "Content-Type: application/json" \
    -d "{\"key_name\":\"document-signing-key\",\"message_b64\":\"SGVsbG8gTWluaSBWYXVsdD8=\",\"message_type\":\"RAW\",\"signature_b64\":\"$SIG\"}" | jq .

section "0.1 — Lock vault, sau do KV/Transit phai tra VAULT_LOCKED (HTTP 423)"
req 'POST /api/v1/vault/lock'
curl -s -X POST "$BASE/api/v1/vault/lock" | jq .
req 'GET /api/v1/kv/secret/alice@example.com/database (sau khi lock)'
curl -s -w '\nHTTP_STATUS:%{http_code}\n' "$BASE/api/v1/kv/secret/alice@example.com/database" -H "Authorization: Bearer $ALICE_TOKEN"

section "HOAN TAT"
echo "Toan bo 8 muc bat buoc (0.1, 0.2, 1.1, 1.2, 2.1, 2.2, 2.3, 2.4) da chay xong."
echo "Xem docs/DEMO_SCRIPT.md de biet cach dung transcript nay cho bao cao / video."
