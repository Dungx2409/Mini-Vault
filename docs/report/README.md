# Báo cáo (chưa hoàn thành — người phụ trách báo cáo xem checklist dưới đây)

Đặt file PDF tại đây với tên chính xác: `Report_MSSV1_MSSV2_MSSV3.pdf`.

Theo mục VI của đề, báo cáo phải có:

- [ ] Tên nhóm, MSSV, **phân công vai trò từng thành viên**
- [ ] Sơ đồ kiến trúc (có sẵn 2 sơ đồ ASCII trong `README.md` gốc để vẽ lại)
- [ ] Giải thích kỹ thuật cho đủ 8 mục: 0.1, 0.2, 1.1, 1.2, 2.1, 2.2, 2.3, 2.4
- [ ] Screenshot demo (theo kịch bản `docs/api-demo.http`)
- [ ] Advanced features đã làm: **không có** (không ghi nhận audit log là advanced —
      audit log hiện tại chưa hash-chained)

Các quyết định thiết kế **bắt buộc phải nêu trong báo cáo** (đề yêu cầu rõ):

1. **Trùng `key_name` (mục 2.1)**: nhóm chọn **từ chối** với lỗi `KEY_ALREADY_EXISTS` (409),
   không hỏi ghi đè — đề cho phép chọn một trong hai nhưng phải ghi rõ lựa chọn.
2. **`message_type=RAW` với Ed25519 (mục 2.4)**: hệ ký thẳng message gốc, KHÔNG hash SHA-256
   trước, vì Ed25519 (PureEdDSA) tự hash nội bộ bằng SHA-512 và thư viện `cryptography`
   không cung cấp chế độ prehash cho Ed25519. `DIGEST` = client tự hash SHA-256, server kiểm
   tra đúng 32 byte rồi ký digest đó như một message. (Xem mục "Ed25519 DIGEST" trong README.)
3. **Chỉ hỗ trợ một `signing_algorithm` là ED25519** (đề cho phép: "e.g., RSA-2048 ... or
   ED25519"). `verify()` nhận thêm trường `signing_algorithm` tùy chọn và từ chối bằng
   `INVALID_SIGNING_ALGORITHM` nếu không khớp thuật toán của key — đúng error case của đề.
4. **Data contract KV**: tag GCM được lưu gộp trong `ciphertext_b64` (chuẩn output
   `ct || tag` của thư viện `cryptography`), tương đương về mật mã với việc tách `tag_b64`.
5. **Định dạng ciphertext Transit**: `vault:v1:<key_name>:<b64(nonce||ct||tag)>` — thêm
   version `v1` so với dạng `vault:<key_name>:...` trong đề, để hỗ trợ key rotation về sau.

Sau khi có PDF, xóa file README.md này rồi đóng gói bằng:

```bash
scripts/package.sh MSSV1 MSSV2 MSSV3
```
