package com.securitylab.pathtraversal.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Lớp cấu hình đường dẫn lưu trữ cho phòng Lab.
 * Giúp tập trung quản lý và dễ dàng thay đổi đường dẫn mà không cần sửa mã nguồn (12-Factor App).
 */
@Configuration
@ConfigurationProperties(prefix = "lab.storage")
public class FileStorageProperties {

    /**
     * Thư mục hợp lệ mà ứng dụng cho phép người dùng truy cập (mặc định: lab-sandbox/uploads).
     */
    private String baseDir = "lab-sandbox/uploads";

    /**
     * Ranh giới sandbox lớn nhất mà phòng lab được phép mô phỏng (lab-sandbox).
     * Ngăn chặn lab chạm tới filesystem thực sự của máy chủ ngay cả trong kịch bản vulnerable.
     */
    private String sandboxRoot = "lab-sandbox";

    public String getBaseDir() {
        return baseDir;
    }

    public void setBaseDir(String baseDir) {
        this.baseDir = baseDir;
    }

    public String getSandboxRoot() {
        return sandboxRoot;
    }

    public void setSandboxRoot(String sandboxRoot) {
        this.sandboxRoot = sandboxRoot;
    }

    public Path getResolvedBasePath() {
        return Paths.get(baseDir).toAbsolutePath().normalize();
    }

    public Path getResolvedSandboxRootPath() {
        return Paths.get(sandboxRoot).toAbsolutePath().normalize();
    }
}
