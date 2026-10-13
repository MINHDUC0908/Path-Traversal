# LAB PATH TRAVERSAL (CWE-22) — CASE STUDY: CVE-2025-32950
**Công nghệ:** Java 21 LTS | Spring Boot 3.3.4 | Maven Wrapper  
**Mục tiêu:** Mô phỏng nguyên nhân gốc rễ, kỹ thuật khai thác và cách vá tối ưu lỗ hổng Path Traversal theo mô hình **CVE-2025-32950** (Jmix Local File Storage trên Spring Boot).

---

## 1. TỔNG QUAN & CASE STUDY CVE-2025-32950

* **CVE-2025-32950 (CVSS 6.5 - Medium):** Lỗ hổng xảy ra trong module quản lý tệp cục bộ (`jmix-localfs`) chạy trên nền Spring Boot. 
* **Nguyên nhân gốc rễ:** Hàm xử lý đọc tệp ghép trực tiếp tham số đầu vào vào thư mục gốc bằng `baseDir.resolve(input)` mà không chuẩn hóa và không kiểm tra ranh giới thư mục.
* **4 Vector khai thác chính trong Lab:**
  1. **V1 - Relative Traversal:** Sử dụng `../` để thoát khỏi thư mục gốc.
  2. **V2 - Windows Separator:** Sử dụng dấu gạch chéo ngược `..\`.
  3. **V3 - Nested Filter Bypass:** Sử dụng `....//` để qua mặt hàm lọc chuỗi thô sơ `replace("../", "")`.
  4. **V4 - Symlink Escape:** Dùng liên kết mềm trỏ ra ngoài thư mục an toàn.

---

## 2. KIẾN TRÚC LAB & RÀNG BUỘC AN TOÀN

```
[ Client / Browser / curl ]
           │
           ├── GET /api/lab/vulnerable/files/download?filename=...
           │   └──> VulnerableFileService (Ghép chuỗi lỗi + Sandbox Guard bảo vệ OS)
           │
           └── GET /api/lab/secure/files/download?filename=...
               └──> SecureFileService (6 Lớp Defense-in-Depth)
```

* **Thư mục được phép đọc:** `lab-sandbox/uploads/` (`welcome.txt`, `sample-report.txt`).
* **Vùng dữ liệu giả định bí mật:** `lab-sandbox/private-fixtures/` (`simulated_secret_token.txt`).
* **Lab Sandbox Guard:** Chặn đứng mọi payload cố tình thoát ra ngoài phạm vi thư mục lab vào hệ điều hành thật (`C:\Windows\...`).

---

## 3. CÁCH KHỞI CHẠY (WINDOWS 11)

Mở PowerShell tại thư mục dự án và chạy:

```powershell
.\run.ps1
```
*(Hoặc dùng lệnh `.\mvnw.ps1 spring-boot:run`)*.

Khi console xuất hiện dòng:
```text
Tomcat started on port 8080 (http) with context path '/'
>>> [CẢNH BÁO PHÒNG LAB]: VulnerableFileController ĐÃ ĐƯỢC KÍCH HOẠT <<<
```
Ứng dụng đang lắng nghe tại: `http://localhost:8080`.

---

## 4. HƯỚNG DẪN KIỂM THỬ THỰC HÀNH

### Bước 1: Đọc tệp hợp lệ
* **URL:** `http://localhost:8080/api/lab/vulnerable/files/download?filename=welcome.txt`
* **Kết quả (HTTP 200 OK):** Trả về nội dung tệp `welcome.txt`.

### Bước 2: Khai thác Path Traversal (Phiên bản Vulnerable)
* **URL:** `http://localhost:8080/api/lab/vulnerable/files/download?filename=../private-fixtures/simulated_secret_token.txt`
* **Kết quả (HTTP 200 OK — Khai thác thành công):** 
  Đọc trộm được chuỗi bí mật `SECRET_KEY=simulated_jwt_secret_xyz789_only_for_path_traversal_lab`.

### Bước 3: Kiểm chứng bản vá (Phiên bản Secure)
* **URL:** `http://localhost:8080/api/lab/secure/files/download?filename=../private-fixtures/simulated_secret_token.txt`
* **Kết quả (HTTP 400 Bad Request — Bị chặn):** 
  `{"status":400,"error":"Bad Request","message":"Tên tệp không hợp lệ..."}`.

---

## 5. PHƯƠNG PHÁP KHẮC PHỤC TỐI ƯU (SECURE LAB)

Trong [`SecureFileService.java`](src/main/java/com/securitylab/pathtraversal/service/SecureFileService.java), bản vá áp dụng 6 lớp phòng thủ:
1. **Whitelist Regex:** `^[a-zA-Z0-9_-]+(\.[a-zA-Z0-9]{1,10})?$` chặn đứng ký tự điều hướng ngay từ đầu vào.
2. **Path Normalization:** Dùng `Path.normalize()` loại bỏ các phần tử `.` và `..`.
3. **Canonicalization:** Dùng `Path.toRealPath(LinkOption.NOFOLLOW_LINKS)` để hệ điều hành giải quyết triệt để Symbolic Link.
4. **Boundary Containment:** Dùng phép toán so sánh cây thư mục `realPath.startsWith(baseDirectory)`.
5. **Resource Integrity:** Kiểm tra `Files.isRegularFile()` ngăn DoS khi người dùng yêu cầu đọc thư mục.
6. **Error Masking:** Chỉ trả về mã HTTP 400/403/404 với thông điệp chung, không lộ stack trace hay đường dẫn ổ đĩa thật.

---

## 6. KIỂM THỬ TỰ ĐỘNG

Chạy toàn bộ 33 bài test bằng lệnh:
```powershell
.\mvnw.ps1 test
```
* **Kết quả:** `33/33 Tests Passed (0 Failures, 0 Errors)`.
