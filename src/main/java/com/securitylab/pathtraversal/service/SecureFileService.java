package com.securitylab.pathtraversal.service;

import com.securitylab.pathtraversal.config.FileStorageProperties;
import com.securitylab.pathtraversal.exception.FileNotFoundException;
import com.securitylab.pathtraversal.exception.InvalidFileRequestException;
import com.securitylab.pathtraversal.exception.SecurityPathException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.regex.Pattern;

/**
 * Service đọc tệp AN TOÀN (Secure Implementation) tuân thủ triệt để nguyên tắc Secure Coding:
 * 
 * CHIẾN LƯỢC PHÒNG THỦ THEO CHIỀU SÂU (Defense-in-Depth):
 * 1. Lớp 1 (Whitelist Validation): Kiểm tra cú pháp tên tệp bằng Regex nghiêm ngặt.
 * 2. Lớp 2 (Normalization): Sử dụng java.nio.file.Path và normalize() loại bỏ các phần tử '.', '..'.
 * 3. Lớp 3 (Canonicalization & Symlink Resolution): Sử dụng toRealPath() để giải quyết triệt để
 *    mọi liên kết mềm (Symbolic Link) trỏ lén ra ngoài thư mục an toàn.
 * 4. Lớp 4 (Boundary Containment Check): So sánh bằng phép toán logic Path.startsWith(Path),
 *    tuyệt đối không chỉ dùng phép so sánh chuỗi (String.startsWith).
 * 5. Lớp 5 (Resource Integrity): Kiểm tra tệp tin là Regular File (không cho phép đọc thư mục / Directory Listing).
 * 6. Lớp 6 (Error Masking): Trả về ngoại lệ chuẩn hóa, không để lộ đường dẫn nội bộ máy chủ.
 */
@Service("secureFileService")
public class SecureFileService implements FileStorageService {

    private static final Logger log = LoggerFactory.getLogger(SecureFileService.class);

    /**
     * Regex Whitelist: Chỉ cho phép chữ cái (a-z, A-Z), chữ số (0-9), dấu gạch dưới (_),
     * gạch nối (-), và một dấu chấm (.) ngăn cách phần mở rộng hợp lệ.
     * Cấm tuyệt đối: '/', '\', '..', '%', '\0' (Null byte).
     */
    private static final Pattern FILENAME_WHITELIST_PATTERN =
            Pattern.compile("^[a-zA-Z0-9_-]+(\\.[a-zA-Z0-9]{1,10})?$");

    private final Path baseDirectory;

    public SecureFileService(FileStorageProperties properties) {
        // Chuẩn hóa và lấy đường dẫn tuyệt đối cho thư mục gốc an toàn
        this.baseDirectory = properties.getResolvedBasePath();
        try {
            if (!Files.exists(this.baseDirectory)) {
                Files.createDirectories(this.baseDirectory);
            }
        } catch (IOException e) {
            log.error("Không thể khởi tạo thư mục lưu trữ an toàn: [{}]", this.baseDirectory, e);
        }
        log.info("SecureFileService đã khởi tạo với Base Directory an toàn: [{}]", this.baseDirectory);
    }

    @Override
    public Resource loadFileAsResource(String filename) {
        // =========================================================================
        // LỚP 1: KIỂM TRA ĐẦU VÀO VỚI WHITELIST (Input Validation)
        // =========================================================================
        if (filename == null || filename.trim().isEmpty()) {
            throw new InvalidFileRequestException("Tên tệp không được để trống.");
        }

        String trimmedFilename = filename.trim();

        // Kiểm tra null byte injection
        if (trimmedFilename.contains("\0")) {
            log.warn("Security Alert: Phát hiện Null Byte Injection trong tên tệp: [{}]", trimmedFilename);
            throw new SecurityPathException("Ký tự không hợp lệ trong tên tệp.");
        }

        // Kiểm tra whitelist regex
        if (!FILENAME_WHITELIST_PATTERN.matcher(trimmedFilename).matches()) {
            log.warn("Security Alert: Tên tệp không khớp Whitelist: [{}]", trimmedFilename);
            throw new InvalidFileRequestException(
                    "Tên tệp không hợp lệ. Chỉ chấp nhận ký tự chữ, số, dấu gạch nối, gạch dưới và phần mở rộng chuẩn."
            );
        }

        // =========================================================================
        // LỚP 2: GHÉP ĐƯỜNG DẪN VÀ CHUẨN HÓA (Path Normalization)
        // =========================================================================
        Path resolvedPath = this.baseDirectory.resolve(trimmedFilename).normalize();

        // =========================================================================
        // LỚP 3 & 4: XÁC THỰC THỰC TẾ (Canonicalization & Boundary Check)
        // Sử dụng toRealPath() để giải quyết triệt để Symbolic Link và lấy đường dẫn thực tế trên OS
        // =========================================================================
        Path realPath;
        try {
            // toRealPath() sẽ ném NoSuchFileException nếu file không tồn tại
            // và tự động giải quyết các Symbolic Link tới vị trí đích thực sự
            realPath = resolvedPath.toRealPath(LinkOption.NOFOLLOW_LINKS);
        } catch (NoSuchFileException e) {
            log.info("Tệp không tồn tại trong thư mục an toàn: [{}]", trimmedFilename);
            throw new FileNotFoundException("Tệp tin yêu cầu không tồn tại.");
        } catch (IOException e) {
            log.warn("Lỗi khi đọc thuộc tính tệp: [{}]", trimmedFilename, e);
            throw new FileNotFoundException("Không thể truy cập tệp tin yêu cầu.");
        }

        // So sánh ranh giới: Đường dẫn thực tế PHẢI bắt đầu bằng thư mục gốc an toàn
        Path realBaseDirectory;
        try {
            realBaseDirectory = this.baseDirectory.toRealPath();
        } catch (IOException e) {
            realBaseDirectory = this.baseDirectory.toAbsolutePath().normalize();
        }

        if (!realPath.startsWith(realBaseDirectory)) {
            log.warn("Security Alert: Phát hiện cố gắng thoát ranh giới thư mục an toàn! RealPath: [{}], Base: [{}]",
                    realPath, realBaseDirectory);
            throw new SecurityPathException("Truy cập bị từ chối: Đường dẫn nằm ngoài thư mục cho phép.");
        }

        // =========================================================================
        // LỚP 5: KIỂM TRA TÍNH TOÀN VẸN CỦA TÀI NGUYÊN (Resource Integrity)
        // Đảm bảo đối tượng là một tệp thông thường (Regular File), không phải thư mục
        // =========================================================================
        if (!Files.isRegularFile(realPath, LinkOption.NOFOLLOW_LINKS)) {
            log.warn("Yêu cầu đối tượng không phải là Regular File: [{}]", realPath);
            throw new FileNotFoundException("Tài nguyên yêu cầu không phải là tệp tin hợp lệ.");
        }

        // Kiểm tra quyền đọc của tiến trình
        if (!Files.isReadable(realPath)) {
            log.error("Tiến trình không có quyền đọc tệp: [{}]", realPath);
            throw new SecurityPathException("Không có quyền đọc tệp tin này.");
        }

        // =========================================================================
        // LỚP 6: TRẢ VỀ RESOURCE AN TOÀN
        // =========================================================================
        try {
            Resource resource = new UrlResource(realPath.toUri());
            if (!resource.exists() || !resource.isReadable()) {
                throw new FileNotFoundException("Không thể đọc tệp tin yêu cầu.");
            }
            return resource;
        } catch (IOException e) {
            throw new FileNotFoundException("Không thể tạo luồng đọc cho tệp tin: " + trimmedFilename);
        }
    }
}
