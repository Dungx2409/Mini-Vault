# Code Review — Mini Vault

> Review đối chiếu source code hiện tại (`app/`) với đặc tả đề bài Assignment 1 — An ninh máy tính. Thực hiện bằng cách đọc toàn bộ source, chạy test suite (`pytest`, `ruff`), và tự viết script gọi trực tiếp API để verify thực nghiệm các nghi vấn bảo mật.

## Kết quả tổng quan

- **Kiến trúc**: FastAPI + SQLAlchemy, tách module rõ ràng (`core/`, `auth/`, `kv/`, `transit/`, `audit/`).
- **Test**: 8/8 test hiện có **pass** (`pytest -q`).
- **Lint**: `ruff check app tests` — **sạch**, không lỗi.
- **Git hygiene**: không có secret/DB nào bị commit (`.gitignore` che `.env`, `*.db`, `data/*.db`).
- **README**: giải thích kỹ thuật khá sâu (Argon2id, AES-GCM, AAD binding, giới hạn triển khai...).

Đây là bài làm chất lượng cao, vượt kỳ vọng thông thường của một bài tập lớn. Review ban đầu phát hiện **2 bug thật** (đã verify bằng cách gọi API trực tiếp); **cả 2 đã được sửa** — xem trạng thái ở từng mục bên dưới.

> **Cập nhật:** Bug #1 và Bug #2 đã được fix trong `app/transit/service.py`, kèm 2 test regression trong `tests/test_transit.py` (`test_key_existence_not_leaked_across_users`, `test_encrypt_decrypt_empty_plaintext_round_trip`). Toàn bộ 10/10 test pass, `ruff` sạch.

## Đối chiếu 8 mục bắt buộc trong đề

| Mục | Trạng thái | Ghi chú |
|---|---|---|
| 0.1 Init/Unlock | ✅ Đạt | Argon2id, DEK bọc bằng AES-256-GCM, `VaultState` chỉ giữ DEK trong RAM (`app/core/vault_state.py`), luôn `locked` khi restart process (test `test_state_is_locked_on_new_application_lifespan` xác nhận) |
| 0.2 Auth | ✅ Đạt | Argon2id hash password, token lưu dạng SHA-256 digest thay vì raw token (tốt hơn yêu cầu tối thiểu), khóa 5 phút sau 5 lần sai liên tiếp, session hết hạn sau 30 phút |
| 1.1 KV Encrypted-at-rest | ✅ Đạt | AES-256-GCM, nonce mới (`os.urandom(12)`) mỗi lần ghi, tamper 1 byte ciphertext → `DECRYPTION_FAILED` (test `test_kv_crud_tamper_and_access` xác nhận) |
| 1.2 KV Access Control | ✅ Đạt, thiết kế tốt | `validate_path()` (`app/utils/validation.py`) chặn ngay bằng prefix `secret/<email>/` **trước khi** chạm DB hay giải mã — không rò rỉ việc path có tồn tại hay không |
| 2.1 Transit Key Mgmt | ✅ Đạt | `list_keys()` chỉ trả `key_name`/`key_usage`/`algorithm`, không bao giờ trả key thật (test assert bằng cách kiểm tra `encrypted_key_material_b64` không xuất hiện trong response) |
| 2.2 Encrypt/Decrypt | ⚠️ Đạt phần lớn, 1 bug | Round-trip đúng với dữ liệu thường, tamper ciphertext bị từ chối đúng — nhưng xem **Bug #2** |
| 2.3 Transit Access Control | ❌ Vi phạm yêu cầu bảo mật rõ ràng | Xem **Bug #1** |
| 2.4 Sign & Verify | ✅ Đạt, có 1 điểm lệch spec (không phải bug) | Round-trip đúng, tamper message/cross-key đều trả `signature_valid: false`. Xem **Note #3** |

## Bug #1 — Rò rỉ sự tồn tại của `key_name` (vi phạm 2.3) — ✅ ĐÃ SỬA

**File:** `app/transit/service.py:20-28`

```python
def _find(self, email: str, name: str, usage: str | None = None) -> TransitKey:
    self.state.require_dek()
    key = self.db.scalar(select(TransitKey).where(TransitKey.owner_email == email,
                                                 TransitKey.key_name == name))
    if not key:
        # Same-name key owned by another user is deliberately indistinguishable from denied use.
        exists = self.db.scalar(select(TransitKey.id).where(TransitKey.key_name == name))
        raise AppError("PERMISSION_DENIED" if exists else "KEY_NOT_FOUND",
                       "Permission denied" if exists else "Key not found", 403 if exists else 404)
```

**Đã verify bằng cách gọi API trực tiếp:**

```
Bob dùng key_name của Alice (tồn tại, không phải chủ) → 403 PERMISSION_DENIED
Bob dùng key_name bịa hoàn toàn (không tồn tại)        → 404 KEY_NOT_FOUND
```

Hai response khác mã lỗi, khác HTTP status — kẻ tấn công có thể dò xem một `key_name` bất kỳ có tồn tại trong hệ thống hay không (dù không phải chủ sở hữu), chỉ bằng cách phân biệt 403 và 404.

Đề bài yêu cầu rõ ở mục 2.3: *"If they don't match → refuse, WITHOUT performing any encryption/decryption operation, returning a generic error (without disclosing whether that key_name exists)."*

Code hiện tại làm ngược lại — comment trong code ("deliberately indistinguishable from denied use") mô tả sai hành vi thực tế: logic này **chủ động phân biệt** hai trường hợp thay vì gộp chung. README của nhóm cũng viết "Access trái phép chỉ trả lỗi chung" — tuyên bố này đúng với KV nhưng **không đúng** với Transit.

**Cách sửa (đã áp dụng):** bỏ nhánh probe `exists`; khi không tìm thấy key thuộc về `email`, luôn trả `PERMISSION_DENIED`/403 bất kể key có tồn tại (do người khác sở hữu) hay không. Chọn `PERMISSION_DENIED` vì (a) không rò rỉ existence, (b) khớp bảng error case mục 2.3, (c) vẫn kích hoạt audit hook `denied_audit` (chỉ log khi code là `PERMISSION_DENIED`). Nhánh `revoked_at` → 404 giữ nguyên vì chỉ chạm được với key của chính caller, không rò rỉ cross-user.

## Bug #2 — Round-trip thất bại với plaintext rỗng — ✅ ĐÃ SỬA

**File:** `app/transit/service.py:96`

```python
if len(blob) < 29: raise AppError("INVALID_CIPHERTEXT", "Invalid ciphertext", 400)
```

Off-by-one: nonce (12 byte) + tag GCM (16 byte) = 28 byte là độ dài tối thiểu **hợp lệ** khi plaintext rỗng, nhưng điều kiện `< 29` từ chối luôn trường hợp 28 byte hợp lệ này.

**Đã verify bằng cách gọi API trực tiếp:**

```
encrypt(key_name="alice-key", plaintext_b64="")  → 200 OK, trả về ciphertext hợp lệ
decrypt(ciphertext đó)                            → 400 INVALID_CIPHERTEXT
```

Vi phạm acceptance criteria 2.2: *"encrypt followed by decrypt must return the exact original plaintext... across multiple data types (text, JSON, binary base64)"* — binary rỗng là edge case hợp lệ của "binary base64".

**Cách sửa (đã áp dụng):** đổi điều kiện `len(blob) < 29` thành `len(blob) < 28`.

## Note #3 — `message_type=RAW` không hash SHA-256 trước khi ký (lệch spec, không hẳn là bug)

**File:** `app/transit/service.py:104-109`

Đề bài viết: *"message_type is either RAW (the system hashes the message with SHA-256 first) or DIGEST..."*. Code hiện tại ký thẳng message gốc cho cả hai `message_type`, chỉ khác ở chỗ `DIGEST` bắt buộc đúng 32 byte:

```python
def sign(self, email, name, message_b64, message_type):
    key = self._find(email, name, "SIGN_VERIFY"); message = b64d(message_b64)
    if message_type == "DIGEST" and len(message) != 32:
        raise AppError("INVALID_DIGEST_LENGTH", "Digest must be 32 bytes", 400)
    private = Ed25519PrivateKey.from_private_bytes(self._material(key))
    return {"key_name": name, "signature_b64": b64e(private.sign(message)), "signing_algorithm": "ED25519"}
```

Về mặt mật mã học, cách làm này **đúng** cho Ed25519 — EdDSA không nên bị pre-hash trước khi ký (đó là lý do Ed25519 không có chế độ "Prehashed" như RSA/ECDSA), và README của nhóm giải thích đúng điều này ở phần "Ed25519 DIGEST". Nhưng vì đề bài mô tả rõ hành vi RAW phải hash SHA-256 trước (mô hình vốn nhắm tới RSA), nhóm **nên ghi chú rõ trong báo cáo** đây là quyết định thiết kế có chủ đích cho Ed25519, để tránh bị hiểu nhầm là "làm sai đặc tả" khi giám khảo chấm đối chiếu văn bản đề.

Liên quan: `VerifyRequest`/`SignRequest` (`app/schemas.py`) không có field `signing_algorithm`, nên error case *"verify() called with a signing_algorithm that doesn't match the one the key was created with → reject"* không áp dụng được — hệ quả tự nhiên của việc nhóm chỉ hỗ trợ 1 thuật toán (ED25519) toàn hệ thống. Đây là một đơn giản hoá hợp lý, nên nêu trong báo cáo.

## Các vấn đề khác cần xử lý trước khi nộp

- **Thiếu phần nộp bài theo mục VI của đề bài**: chưa thấy `docs/report/` với file `Report_<MSSV1>_<MSSV2>_<MSSV3>.pdf` (kiến trúc, giải thích kỹ thuật từng mục 0.1→2.4, screenshot demo, phân công vai trò), cũng chưa thấy link video demo. Hiện project chỉ có `README.md` kỹ thuật — cần bổ sung báo cáo PDF riêng và video demo (~3-5 phút) trước khi nộp, nếu nhóm chưa làm phần này.
- Cấu trúc thư mục dùng `app/` thay vì `src/` như gợi ý trong đề — đề chỉ "recommended" nên không sai, nhưng nên note rõ trong báo cáo lý do đổi tên.
- `app/middleware/request_logging.py` chỉ có 1 dòng docstring, không được import hay dùng ở bất kỳ đâu trong codebase — là file chết, nên xoá hoặc thực sự implement thành middleware.
- Test hiện có (`test_encrypt_decrypt_binary_access_revoke`) chỉ test trường hợp key tồn tại nhưng thuộc người khác, chưa có test case "key hoàn toàn không tồn tại" — nên thêm test này ngay sau khi sửa Bug #1 để tránh regression.

## Tóm lại

Trừ 2 bug cụ thể ở trên (đều sửa được trong vài dòng), phần code hoàn thành đầy đủ và đúng tinh thần cả 8 mục bắt buộc, có nhiều điểm thiết kế vượt yêu cầu tối thiểu (AAD binding theo owner+key_name, generic-error đúng chuẩn trong KV, lưu token dạng digest thay vì raw). Việc còn thiếu chủ yếu nằm ở phần nộp bài (report PDF + demo video), không phải ở chất lượng code.
