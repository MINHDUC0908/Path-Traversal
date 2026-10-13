package com.securitylab.pathtraversal.service;

import com.securitylab.pathtraversal.config.FileStorageProperties;
import com.securitylab.pathtraversal.exception.FileNotFoundException;
import com.securitylab.pathtraversal.exception.SecurityPathException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Service mô phỏng chức năng đọc tệp CÓ LỖ HỔNG Path Traversal (CWE-22).
 * 
 * NGUYÊN NHÂN GỐC RỄ:
 * Sử dụng trực tiếp dữ liệu đầu vào không tin cậy (untrusted user input) để ghép nối đường dẫn
 * thông qua `basePath.resolve(filename)` mà KHÔNG thực hiện chuẩn hóa (normalize) và KHÔNG
 * kiểm tra xem đường dẫn đích có nằm trong thư mục cho phép (startsWith) hay không.
 * 
 * CƠ CHẾ BẢO VỆ PHÒNG LAB (Lab Sandbox Jail Guard):
 * Mặc dù cho phép khai thác đọc dữ liệu ngoài thư mục uploads (để chứng minh CWE-22),
 * service vẫn có một chốt chặn an toàn nhằm ngăn chặn tuyệt đối việc duyệt ra ngoài toàn bộ
 * thư mục 'lab-sandbox', bảo vệ tuyệt đối filesystem của máy chủ thật.
 */
@Service("vulnerableFileService")
public class VulnerableFileService implements FileStorageService {

    private static final Logger log = LoggerFactory.getLogger(VulnerableFileService.class);

    private final Path basePath;
    private final Path sandboxRootPath;

    public VulnerableFileService(FileStorageProperties properties) {
        this.basePath = properties.getResolvedBasePath();
        this.sandboxRootPath = properties.getResolvedSandboxRootPath();
        log.warn("VulnerableFileService đã được khởi tạo! Base path: [{}], Sandbox root: [{}]",
                basePath, sandboxRootPath);
    }

    @Override
    public Resource loadFileAsResource(String filename) {
        if (filename == null || filename.trim().isEmpty()) {
            throw new FileNotFoundException("Tên tệp không được để trống.");
        }

        // =========================================================================
        // [VULNERABILITY POINT] - DÒNG CODE GÂY RA LỖ HỔNG PATH TRAVERSAL (CWE-22)
        // Ghép trực tiếp untrusted input vào base path mà không kiểm tra ranh giới
        // =========================================================================
        Path targetPath = basePath.resolve(filename);

        log.info("[Vulnerable Path] Yêu cầu: [{}], Đường dẫn được phân giải: [{}]",
                filename, targetPath);

        // =========================================================================
        // [LAB SANDBOX JAIL GUARD] - RANH GIỚI BẢO VỆ MÁY CHỦ THẬT
        // Cho phép thoát khỏi `uploads/` sang `private-fixtures/` để chứng minh lỗi,
        // nhưng chặn đứng nếu cố tình thoát ra ngoài toàn bộ `lab-sandbox/` vào OS.
        // =========================================================================
        Path normalizedAbsolute = targetPath.toAbsolutePath().normalize();
        if (!normalizedAbsolute.startsWith(sandboxRootPath)) {
            log.error("[Sandbox Guard Alert] Phát hiện nỗ lực duyệt ra ngoài phạm vi Lab Sandbox: [{}]",
                    normalizedAbsolute);
            throw new SecurityPathException(
                    "Lab Sandbox Guard: Bị từ chối vì đường dẫn vượt quá phạm vi phòng lab giả lập."
            );
        }

        try {
            Resource resource = new UrlResource(targetPath.toUri());

            // Kiểm tra tệp có tồn tại và đọc được hay không
            if (!resource.exists() || !resource.isReadable() || Files.isDirectory(targetPath)) {
                throw new FileNotFoundException("Không tìm thấy tệp hoặc tệp là một thư mục: " + filename);
            }

            return resource;
        } catch (IOException e) {
            throw new FileNotFoundException("Không thể đọc tệp yêu cầu: " + filename);
        }
    }
}
