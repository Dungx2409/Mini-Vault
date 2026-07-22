# Test data files (yêu cầu mục VI của đề)

Toàn bộ file trong thư mục này được sinh bằng chính ứng dụng (không giả lập mật mã) qua
`python scripts/make_samples.py`. Script tự kiểm chứng: không một plaintext nào của secret,
passphrase hay message xuất hiện trong file DB trên disk.

| File | Nội dung |
|---|---|
| `sample_vault.db` | File dữ liệu KV/Transit **đã mã hóa** (SQLite): vault config (DEK đã bọc), user, 2 KV secret, 2 named key, audit log |
| `transit_ciphertext.txt` | Một ciphertext self-describing của Transit (`vault:v1:payment-key:...`) |
| `transit_samples.json` | Bộ dữ liệu round-trip đầy đủ: plaintext/ciphertext của encrypt-decrypt và message/signature của sign-verify |
| `../logs/audit_log_sample.txt` | Audit log mẫu, gồm 2 truy cập cross-user bị DENIED (KV read + Transit encrypt) |

## Thông tin đăng nhập của dữ liệu mẫu

- Master Passphrase: `Sample-Master-Passphrase-2026!`
- `alice@example.com` / `AliceSample@2026` — sở hữu 2 secret (`secret/alice@example.com/database`,
  `secret/alice@example.com/payment-gateway`) và 2 named key (`payment-key`, `document-signing-key`)
- `bob@example.com` / `BobSample@2026!!` — không sở hữu gì; các lần truy cập chéo của Bob bị từ
  chối và đã ghi trong audit log

## Cách kiểm chứng

```bash
# Mở file DB bằng text editor hoặc `strings sample_vault.db`: không thấy plaintext secret nào.
DATABASE_URL=sqlite:///./data/samples/sample_vault.db uvicorn app.main:app
# 1. POST /api/v1/vault/unlock với Master Passphrase ở trên (mới khởi động luôn là locked)
# 2. POST /api/v1/auth/login bằng Alice, đọc GET /api/v1/kv/secret/alice@example.com/database
# 3. POST /api/v1/transit/decrypt với ciphertext trong transit_ciphertext.txt (token Alice)
# 4. POST /api/v1/transit/verify với message/signature trong transit_samples.json
```

Chạy lại `python scripts/make_samples.py` sẽ tạo mới toàn bộ (ciphertext/chữ ký sẽ khác vì
DEK, key, nonce đều sinh ngẫu nhiên mỗi lần).
