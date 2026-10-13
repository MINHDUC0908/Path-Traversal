package com.securitylab.pathtraversal;

import com.securitylab.pathtraversal.config.FileStorageProperties;
import com.securitylab.pathtraversal.exception.FileNotFoundException;
import com.securitylab.pathtraversal.exception.SecurityPathException;
import com.securitylab.pathtraversal.service.VulnerableFileService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("Kiểm thử VulnerableFileService (Mô phỏng lỗ hổng CWE-22)")
class VulnerableFileServiceTest {

    private VulnerableFileService vulnerableFileService;

    @BeforeEach
    void setUp() {
        FileStorageProperties properties = new FileStorageProperties();
        properties.setBaseDir("lab-sandbox/uploads");
        properties.setSandboxRoot("lab-sandbox");
        this.vulnerableFileService = new VulnerableFileService(properties);
    }

    @Test
    @DisplayName("1. Truy cập hợp lệ: Đọc tệp welcome.txt trong thư mục uploads")
    void shouldReadLegitimateFileSuccessfully() throws IOException {
        // Given
        String filename = "welcome.txt";

        // When
        Resource resource = vulnerableFileService.loadFileAsResource(filename);

        // Then
        assertThat(resource.exists()).isTrue();
        String content = resource.getContentAsString(StandardCharsets.UTF_8);
        assertThat(content).contains("Xin chào! Đây là tệp tin công khai hợp lệ");
    }

    @Test
    @DisplayName("2. Khai thác Path Traversal: Đọc tệp bí mật giả lập nằm ngoài thư mục uploads (CWE-22)")
    void shouldDemonstratePathTraversalVulnerability() throws IOException {
        // Given: Payload sử dụng '../' để thoát khỏi thư mục uploads sang private-fixtures
        String maliciousPayload = "../private-fixtures/simulated_secret_token.txt";

        // When: Gọi service có lỗ hổng
        Resource resource = vulnerableFileService.loadFileAsResource(maliciousPayload);

        // Then: Khai thác thành công! Tệp tin ngoài phạm vi uploads bị đọc trộm
        assertThat(resource.exists()).isTrue();
        String content = resource.getContentAsString(StandardCharsets.UTF_8);
        assertThat(content).contains("SECRET_KEY=simulated_jwt_secret_xyz789_only_for_path_traversal_lab");
    }

    @Test
    @DisplayName("3. Ranh giới an toàn của Lab: Chặn đứng truy cập thoát ra ngoài toàn bộ lab-sandbox")
    void shouldBlockTraversalEscapingEntireLabSandbox() {
        // Given: Payload cố gắng thoát ra tận filesystem của hệ điều hành
        String dangerousPayload = "../../../../Windows/win.ini";

        // When & Then: Phải bị Lab Sandbox Guard chặn lại để bảo vệ máy chủ
        assertThatThrownBy(() -> vulnerableFileService.loadFileAsResource(dangerousPayload))
                .isInstanceOf(SecurityPathException.class)
                .hasMessageContaining("Lab Sandbox Guard");
    }

    @Test
    @DisplayName("4. Xử lý tệp không tồn tại")
    void shouldThrowExceptionWhenFileDoesNotExist() {
        // Given
        String nonExistentFile = "unknown_document.txt";

        // When & Then
        assertThatThrownBy(() -> vulnerableFileService.loadFileAsResource(nonExistentFile))
                .isInstanceOf(FileNotFoundException.class);
    }
}
