# LAB MÔ PHỎNG & PHÒNG THỦ LỖ HỔNG PATH TRAVERSAL (CWE-22)
**Case Study:** CVE-2025-32950 (Spring Boot Local File Storage)  
**Công nghệ:** Java 21 LTS | Spring Boot 3.3.4 | Maven Wrapper | JUnit 5 & MockMvc  

---

## 1. TỔNG QUAN & CASE STUDY CVE-2025-32950

* **CVE-2025-32950 (CVSS 6.5 - Medium):** Lỗ hổng Path Traversal trong module `jmix-localfs` (chạy trên nền Spring Boot) khi hàm xử lý tệp tin ghép trực tiếp chuỗi tham chiếu (`fileRef`) do người dùng nhập vào thư mục lưu trữ cục bộ.
* **4 Vector khai thác cốt lõi trong Lab:**
  1. **V1 - Relative Path Traversal:** Dùng `../` để thoát khỏi thư mục gốc `uploads/`.
  2. **V2 - Windows Path Traversal:** Dùng dấu `..\` trên hệ điều hành Windows.
  3. **V3 - Nested Filter Bypass:** Dùng `....//` để vượt qua bộ lọc blacklist thô sơ `replace("../", "")`.
  4. **V4 - Symlink Escape:** Dùng Symbolic Link trỏ lén ra ngoài tệp nhạy cảm.

---

## 2. CẤU TRÚC PHÒNG LAB & DỮ LIỆU CÔ LẬP

```
lab-sandbox/
├── uploads/              <-- [Public Scope] Thư mục được phép đọc (welcome.txt, sample-report.txt)
└── private-fixtures/     <-- [Restricted Scope] Vùng giả lập tài nguyên mật (simulated_secret_token.txt)
```

* **Ranh giới an toàn (Lab Sandbox Guard):** Ngay cả ở phiên bản có lỗi (`VulnerableFileService`), hệ thống có một chốt chặn bảo vệ: nếu payload cố tình nhảy ra ngoài toàn bộ thư mục `lab-sandbox/` (ví dụ `C:\Windows\...`), hệ thống sẽ từ chối ngay lập tức để bảo vệ tuyệt đối máy chủ thật.

---

## 3. HƯỚNG DẪN KHỞI CHẠY (CHUẨN 2 TERMINAL)

Để quan sát trực quan nhất quá trình tấn công và phòng thủ, hãy mở **2 tab Terminal** song song trong IDE:

### 3.1. Terminal 1: Khởi động Server ứng dụng
Tại thư mục gốc dự án (`d:\Bảo mật\Path Traversal`), chạy một trong hai lệnh:

```powershell
# Cách 1 (Khuyên dùng - Nhanh nhất):
.\run.ps1

# Cách 2 (Dùng Maven Wrapper):
.\mvnw.ps1 spring-boot:run
```

**Dấu hiệu thành công:** Màn hình xuất hiện thông báo:
```text
Tomcat started on port 8080 (http) with context path '/'
Started PathTraversalLabApplication in 1.651 seconds
>>> [CẢNH BÁO PHÒNG LAB]: VulnerableFileController ĐÃ ĐƯỢC KÍCH HOẠT <<<
```
*(Server đang hoạt động và lắng nghe tại `http://localhost:8080`).*

---

### 3.2. Terminal 2: Thực thi kịch bản tấn công (Attacker)
Mở một tab PowerShell thứ hai và chạy script tấn công tự động:

```powershell
.\exploit_demo.ps1
```

Script sẽ tự động gửi toàn bộ 4 vector tấn công và hiển thị bảng so sánh trực tiếp:
- **Nhánh Vulnerable:** Trả về `HTTP 200 OK` kèm nội dung bị rò rỉ `SECRET_KEY=simulated_jwt_secret_xyz789...` *(Khai thác thành công)*.
- **Nhánh Secure:** Bị chặn đứng với `HTTP 400 Bad Request` *(Bản vá hoạt động)*.

*(Để dừng server ở Terminal 1 khi kết thúc buổi thực hành: Nhấn **`Ctrl + C`**)*.

---

## 4. CÁCH KIỂM THỬ THỦ CÔNG QUA TRÌNH DUYỆT (CHỤP ẢNH BẰNG CHỨNG)

Bạn có thể dán trực tiếp các URL dưới đây vào trình duyệt (Chrome/Edge) hoặc dùng Postman:

| Mục đích | URL kiểm thử | Kết quả mong đợi |
| :--- | :--- | :--- |
| **1. Đọc tệp hợp lệ** | `http://localhost:8080/api/lab/vulnerable/files/download?filename=welcome.txt` | `HTTP 200 OK`: Tải tệp chào mừng công khai. |
| **2. Tấn công có lỗi (Proof-of-Concept)** | `http://localhost:8080/api/lab/vulnerable/files/download?filename=../private-fixtures/simulated_secret_token.txt` | `HTTP 200 OK`: **Đọc trộm được Secret Token** *(Minh họa lỗ hổng CWE-22)*. |
| **3. Kiểm tra bản vá bảo mật** | `http://localhost:8080/api/lab/secure/files/download?filename=../private-fixtures/simulated_secret_token.txt` | `HTTP 400 Bad Request`: Bị chặn bởi Regex Whitelist & Boundary Check. |

---

## 5. CÁCH VÁ LỖ HỔNG & TẠI SAO BẢN VÁ HIỆU QUẢ

### 5.1. So sánh trực diện mã nguồn (Trước vs Sau khi vá)

#### ❌ Mã nguồn trước khi vá (`VulnerableFileService.java` - Mô hình gây lỗi CVE-2025-32950):
```java
// NGUYÊN NHÂN GỐC RỄ: Ghép chuỗi logic mà không kiểm tra ranh giới
Path targetPath = basePath.resolve(filename);
Resource resource = new UrlResource(targetPath.toUri());
return resource;
```
* **Vì sao lỗi?** Phương thức `resolve()` chỉ ghép chuỗi. Khi `filename` có `../`, hệ điều hành tự động lùi về thư mục cha và đọc trộm tệp ngoài thư mục cho phép.

---

#### ✅ Mã nguồn sau khi vá (`SecureFileService.java` - 4 Bước phòng thủ tối ưu):
```java
// BƯỚC 1: Whitelist Input Validation (Chặn ký tự điều hướng ngay từ cửa ngõ)
private static final Pattern FILENAME_WHITELIST = 
        Pattern.compile("^[a-zA-Z0-9_-]+(\\.[a-zA-Z0-9]{1,10})?$");

if (!FILENAME_WHITELIST.matcher(filename).matches()) {
    throw new InvalidFileRequestException("Tên tệp không hợp lệ!");
}

// BƯỚC 2: Chuẩn hóa và giải quyết Symbolic Link trên đĩa vật lý
Path resolvedPath = this.baseDirectory.resolve(filename).normalize();
Path realPath = resolvedPath.toRealPath(LinkOption.NOFOLLOW_LINKS);
Path realBaseDir = this.baseDirectory.toRealPath();

// BƯỚC 3: Kiểm tra ranh giới cây thư mục (Boundary Containment)
if (!realPath.startsWith(realBaseDir)) {
    throw new SecurityPathException("Truy cập bị từ chối: Đường dẫn nằm ngoài thư mục cho phép!");
}

// BƯỚC 4: Kiểm tra tính toàn vẹn (Không cho phép đọc thư mục)
if (!Files.isRegularFile(realPath, LinkOption.NOFOLLOW_LINKS)) {
    throw new FileNotFoundException("Tài nguyên không phải là tệp tin hợp lệ!");
}
```

---

### 5.2. Giải thích lý do bản vá hiệu quả tuyệt đối

1. **Whitelist thay vì Blacklist:** 
   - Không cố gắng lọc `../` bằng `replace()` (vì dễ bị bypass bởi `....//` hoặc encoding).
   - Whitelist chỉ chấp nhận ký tự chữ, số, gạch ngang, gạch dưới. Mọi ký tự `/`, `\`, `.`, `%` bất thường đều bị loại bỏ ngay từ đầu.
2. **Khử Symbolic Link với `toRealPath(LinkOption.NOFOLLOW_LINKS)`:**
   - Ngăn chặn kỹ thuật tấn công Symlink Redirection (kẻ tấn công tạo liên kết mềm trỏ lén ra ngoài tệp nhạy cảm).
3. **Phép so sánh logic `Path.startsWith(Path)`:**
   - So sánh từng nút nốt trên cây phân cấp thư mục của OS, tránh lỗi chuỗi giả mạo tiền tố (prefix string match bug).
4. **Xử lý lỗi an toàn (Safe Error Masking):**
   - Kết hợp `GlobalExceptionHandler` chỉ trả về mã lỗi HTTP 400 hoặc 403, che giấu hoàn toàn đường dẫn nội bộ và stack trace của máy chủ.

---

## 6. KIỂM THỬ HỒI QUY TỰ ĐỘNG (REGRESSION TESTING)

Toàn bộ 33 kịch bản kiểm thử bảo mật (bao gồm cả unit test, integration test MockMvc và regression test) được chạy tự động bằng lệnh:

```powershell
.\mvnw.ps1 test
```

* **Kết quả:** `33/33 Tests Passed (0 Failures, 0 Errors)` — Chứng minh bản vá hoạt động ổn định và tin cậy 100%.
