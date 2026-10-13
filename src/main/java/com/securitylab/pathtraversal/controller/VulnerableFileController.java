package com.securitylab.pathtraversal.controller;

import com.securitylab.pathtraversal.service.FileStorageService;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

/**
 * Controller cung cấp API đọc tệp CÓ LỖ HỔNG Path Traversal.
 * 
 * ĐIỀU KIỆN KHỞI CHẠY BẢO MẬT:
 * Được gắn annotation @ConditionalOnProperty: Endpoint này CHỈ TỒN TẠI khi cấu hình
 * 'lab.security.allow-vulnerable-endpoint=true' (chỉ có trong profile 'lab').
 * Trong môi trường production thực tế, controller này sẽ hoàn toàn bị vô hiệu hóa,
 * không bao giờ được đưa vào ApplicationContext của Spring.
 */
@RestController
@RequestMapping("/api/lab/vulnerable/files")
@ConditionalOnProperty(
        name = "lab.security.allow-vulnerable-endpoint",
        havingValue = "true",
        matchIfMissing = false
)
public class VulnerableFileController {

    private static final Logger log = LoggerFactory.getLogger(VulnerableFileController.class);

    private final FileStorageService vulnerableFileService;

    public VulnerableFileController(@Qualifier("vulnerableFileService") FileStorageService vulnerableFileService) {
        this.vulnerableFileService = vulnerableFileService;
        log.warn(">>> [CẢNH BÁO PHÒNG LAB]: VulnerableFileController ĐÃ ĐƯỢC KÍCH HOẠT <<<");
    }

    /**
     * Cách 1: Đọc tệp qua Query Parameter (phương thức phổ biến nhất để kiểm thử khai thác Path Traversal qua HTTP)
     * Ví dụ:
     * GET /api/lab/vulnerable/files/download?filename=welcome.txt
     * GET /api/lab/vulnerable/files/download?filename=../private-fixtures/simulated_secret_token.txt
     */
    @GetMapping("/download")
    public ResponseEntity<Resource> downloadFileByParam(@RequestParam("filename") String filename) {
        log.info("[Vulnerable Controller] Nhận yêu cầu tải tệp qua param: [{}]", filename);
        return serveResource(filename);
    }

    /**
     * Cách 2: Đọc tệp qua Path Variable wildcard Spring 6+ {*filename}
     * Hỗ trợ bắt toàn bộ đường dẫn con phía sau, bao gồm cả dấu gạch chéo điều hướng.
     * Ví dụ:
     * GET /api/lab/vulnerable/files/view/welcome.txt
     * GET /api/lab/vulnerable/files/view/..%2fprivate-fixtures%2fsimulated_secret_token.txt
     */
    @GetMapping("/view/{*filepath}")
    public ResponseEntity<Resource> viewFileByPath(@PathVariable("filepath") String filepath) {
        // Loại bỏ dấu '/' ở đầu nếu Spring Wildcard tự động thêm vào
        String cleanPath = filepath.startsWith("/") ? filepath.substring(1) : filepath;
        log.info("[Vulnerable Controller] Nhận yêu cầu tải tệp qua path: [{}]", cleanPath);
        return serveResource(cleanPath);
    }

    private ResponseEntity<Resource> serveResource(String filename) {
        // Chuyển trực tiếp dữ liệu người dùng tới Service mà không qua lọc hay xác thực
        Resource resource = vulnerableFileService.loadFileAsResource(filename);

        String contentType = "text/plain; charset=UTF-8";
        try {
            if (resource.getFile().getName().endsWith(".json")) {
                contentType = MediaType.APPLICATION_JSON_VALUE;
            } else if (resource.getFile().getName().endsWith(".pdf")) {
                contentType = MediaType.APPLICATION_PDF_VALUE;
            }
        } catch (IOException ignored) {
            // Giữ contentType mặc định
        }

        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(contentType))
                .header(HttpHeaders.CONTENT_DISPOSITION, "inline; filename=\"" + resource.getFilename() + "\"")
                .body(resource);
    }
}
