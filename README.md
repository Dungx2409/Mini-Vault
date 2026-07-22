# Mini Vault

Mini Vault là REST API quản lý secret và cung cấp mật mã như một dịch vụ, mô phỏng một phần
HashiCorp Vault/AWS KMS. Client có thể lưu JSON đã mã hóa, encrypt/decrypt, sign/verify nhưng
không bao giờ nhận DEK, named AES key hay Ed25519 private key.

## Kiến trúc

```text
Client
  ↓ REST API
FastAPI
  ├── Authentication
  ├── Vault Core
  ├── KV Engine
  ├── Transit Engine
  └── Audit Log
          ↓
       SQLite
```

```text
Master Passphrase (không lưu)
        ↓ Argon2id + random salt
Derived Key (chỉ RAM trong lúc unlock)
        ↓ AES-256-GCM
Encrypted DEK (lưu DB) → plaintext DEK chỉ ở RAM khi unlocked
        ↓ AES-256-GCM
Secret JSON / Named AES key / Ed25519 private key
```

Ứng dụng luôn lock khi process khởi động. `VaultState` là mutable state có khóa đồng bộ duy
nhất, giữ DEK trong RAM; trạng thái unlock không được ghi vào DB.

## Cài đặt

Yêu cầu Python 3.11+.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
mkdir -p data
uvicorn app.main:app --reload
```

Swagger ở `http://localhost:8000/docs`, ReDoc ở `/redoc`, health check ở `/health`.

## Docker

```bash
docker compose up --build
```

Container chạy bằng user không phải root; volume `vault-data` giữ SQLite tại `/app/data`.

## Kiểm thử

```bash
pytest -v
ruff check app tests
```

Test dùng SQLite riêng, reset schema giữa từng test, không dùng database production và không
`sleep(300)` khi kiểm tra lockout/expiry.

## API

| Nhóm | Method và path | Chức năng |
|---|---|---|
| Vault | `POST /api/v1/vault/init` | Tạo salt, derive key, sinh và bọc DEK; vẫn locked |
| Vault | `POST /api/v1/vault/unlock` | Derive lại key và đưa DEK vào RAM |
| Vault | `POST /api/v1/vault/lock` | Xóa tham chiếu DEK khỏi state |
| Vault | `GET /api/v1/vault/status` | Trạng thái không chứa key material |
| Auth | `POST /api/v1/auth/register` | Argon2id password hash |
| Auth | `POST /api/v1/auth/login` | Session 30 phút, DB chỉ lưu SHA-256 token digest |
| Auth | `POST /api/v1/auth/logout` | Revoke session |
| Auth | `GET /api/v1/auth/me` | User hiện tại |
| KV | `GET /api/v1/kv` | Danh sách metadata của owner |
| KV | `PUT/GET/DELETE /api/v1/kv/{path}` | CRUD JSON secret đã mã hóa |
| Transit | `POST/GET /api/v1/transit/keys` | Tạo AES key / list metadata |
| Transit | `GET/DELETE /api/v1/transit/keys/{name}` | Metadata / revoke |
| Transit | `POST /api/v1/transit/encrypt` | Encrypt bytes Base64 |
| Transit | `POST /api/v1/transit/decrypt` | Decrypt self-describing ciphertext |
| Transit | `POST /api/v1/transit/signing-keys` | Tạo Ed25519 key pair |
| Transit | `POST /api/v1/transit/sign` | Sign RAW hoặc digest 32-byte |
| Transit | `POST /api/v1/transit/verify` | Verify; chữ ký sai trả `signature_valid=false` |

Mọi API Auth/KV/Transit cần `Authorization: Bearer <token>`, trừ register/login. Auth được kiểm
tra trước trạng thái vault. Response nghiệp vụ có envelope `success/data/error`; health giữ
response tối giản theo đặc tả.

### Ciphertext transit

Định dạng là `vault:v1:<key_name>:<base64(nonce || ciphertext || tag)>`. Nonce dài 12 byte.
`cryptography.AESGCM.encrypt` trả `ciphertext || tag` (tag 16 byte); AAD gắn version, owner và
key name nên không thể đổi ngữ cảnh ciphertext. KV dùng path làm AAD. Mỗi lần encrypt đều lấy
nonce mới từ `os.urandom`.

Key được **soft revoke** qua `revoked_at` để audit metadata nội bộ; mọi crypto operation và API
metadata bắt buộc từ chối key đã revoke.

### Ed25519 DIGEST

Ed25519 không có chế độ `Prehashed` như RSA. Với `message_type=DIGEST`, API kiểm tra đúng 32
byte rồi ký chính 32 byte đó như một message Ed25519. Client chịu trách nhiệm tạo SHA-256 digest.

## Luồng demo

File [docs/api-demo.http](docs/api-demo.http) chứa request có thể chạy tuần tự:

1. Init và unlock vault.
2. Register Alice và Bob, login và copy token.
3. Alice ghi/đọc `secret/alice@example.com/database`; thay bằng token Bob để thấy 403.
4. Alice tạo `payment-key`, encrypt/decrypt text; token Bob không dùng được key đó.
5. Alice tạo `document-signing-key`, sign rồi verify message.
6. Thay một byte message để nhận `signature_valid: false`.
7. Lock vault, sau đó KV/Transit trả `VAULT_LOCKED` với HTTP 423.

## Quyết định bảo mật

- Argon2id là memory-hard KDF/password hasher, giảm hiệu quả brute-force bằng GPU. Password
  hashing là phép một chiều để xác thực; encryption là phép đảo ngược có khóa cho dữ liệu.
- AES-256-GCM cung cấp confidentiality và integrity. Nonce phải duy nhất với mỗi key; tái sử dụng
  nonce GCM có thể làm lộ plaintext và phá authentication.
- DEK plaintext và derived key không lưu xuống disk. Master passphrase cũng không lưu hay log.
- Private signing key được DEK bọc trước khi ghi DB; public key có thể plaintext vì không bí mật.
- Authorization chạy trước khi đọc ciphertext/decrypt key material. Access trái phép chỉ trả lỗi
  chung và ghi requester/action/resource/result/IP, không ghi plaintext hoặc key material.
- Token có 256 bit entropy từ `secrets.token_urlsafe(32)`; DB chỉ giữ digest và kiểm tra bằng
  `compare_digest`. Account lock 5 phút sau năm lần sai.
- Base64 được decode với validation nghiêm ngặt; key name/path được whitelist; `..`, backslash,
  NUL và namespace khác owner bị chặn. Payload được giới hạn xấp xỉ 1 MiB.

## Giới hạn triển khai

SQLite phù hợp project học tập/single instance. Vì DEK ở RAM theo process, không chạy nhiều
Uvicorn worker độc lập nếu không có thiết kế unseal phân tán. Python không bảo đảm zeroize bytes
tuyệt đối; `lock` loại bỏ tham chiếu state tốt nhất trong giới hạn runtime managed-memory.
