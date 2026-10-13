package com.securitylab.pathtraversal.controller;

import com.securitylab.pathtraversal.service.FileStorageService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

/**
 * Controller cung cấp API đọc tệp AN TOÀN (Secure Lab API).
 * Triển khai theo nguyên tắc Secure by Default:
 * - Tiếp nhận tham số và chuyển cho SecureFileService kiểm soát nghiêm ngặt.
 * - Trả về Content-Type và Content-Disposition an toàn.
 * - Mọi ngoại lệ vi phạm sẽ được GlobalExceptionHandler chuyển đổi thành HTTP 400 hoặc 403.
 */
@RestController
@RequestMapping("/api/lab/secure/files")
public class SecureFileController {

    private static final Logger log = LoggerFactory.getLogger(SecureFileController.class);

    private final FileStorageService secureFileService;

    public SecureFileController(@Qualifier("secureFileService") FileStorageService secureFileService) {
        this.secureFileService = secureFileService;
    }

    /**
     * Tải tệp qua query param an toàn.
     * Ví dụ:
     * GET /api/lab/secure/files/download?filename=welcome.txt
     */
    @GetMapping("/download")
    public ResponseEntity<Resource> downloadFileByParam(@RequestParam("filename") String filename) {
        log.info("[Secure Controller] Nhận yêu cầu đọc tệp qua param: [{}]", filename);
        return serveResource(filename);
    }

    /**
     * Tải tệp qua path variable an toàn.
     * Ví dụ:
     * GET /api/lab/secure/files/view/welcome.txt
     */
    @GetMapping("/view/{*filepath}")
    public ResponseEntity<Resource> viewFileByPath(@PathVariable("filepath") String filepath) {
        String cleanPath = filepath.startsWith("/") ? filepath.substring(1) : filepath;
        log.info("[Secure Controller] Nhận yêu cầu đọc tệp qua path: [{}]", cleanPath);
        return serveResource(cleanPath);
    }

    private ResponseEntity<Resource> serveResource(String filename) {
        Resource resource = secureFileService.loadFileAsResource(filename);

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
