package com.securitylab.pathtraversal;

import com.securitylab.pathtraversal.config.FileStorageProperties;
import com.securitylab.pathtraversal.exception.FileNotFoundException;
import com.securitylab.pathtraversal.exception.InvalidFileRequestException;
import com.securitylab.pathtraversal.exception.SecurityPathException;
import com.securitylab.pathtraversal.service.SecureFileService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("Kiểm thử SecureFileService (Phòng thủ đa tầng trước Path Traversal)")
class SecureFileServiceTest {

    private SecureFileService secureFileService;

    @BeforeEach
    void setUp() {
        FileStorageProperties properties = new FileStorageProperties();
        properties.setBaseDir("lab-sandbox/uploads");
        properties.setSandboxRoot("lab-sandbox");
        this.secureFileService = new SecureFileService(properties);
    }

    @Test
    @DisplayName("1. Truy cập hợp lệ: Đọc tệp welcome.txt thành công")
    void shouldReadLegitimateFileSuccessfully() throws IOException {
        // Given
        String legitimateFilename = "welcome.txt";

        // When
        Resource resource = secureFileService.loadFileAsResource(legitimateFilename);

        // Then
        assertThat(resource.exists()).isTrue();
        String content = resource.getContentAsString(StandardCharsets.UTF_8);
        assertThat(content).contains("Xin chào! Đây là tệp tin công khai hợp lệ");
    }

    @Test
    @DisplayName("2. Truy cập hợp lệ: Đọc tệp sample-report.txt có dấu gạch nối")
    void shouldReadSecondLegitimateFileSuccessfully() throws IOException {
        // Given
        String legitimateFilename = "sample-report.txt";

        // When
        Resource resource = secureFileService.loadFileAsResource(legitimateFilename);

        // Then
        assertThat(resource.exists()).isTrue();
        String content = resource.getContentAsString(StandardCharsets.UTF_8);
        assertThat(content).contains("BÁO CÁO KINH DOANH MẪU");
    }

    @ParameterizedTest(name = "Kịch bản chặn: {0}")
    @ValueSource(strings = {
            "../private-fixtures/simulated_secret_token.txt",
            "..\\private-fixtures\\simulated_secret_token.txt",
            "....//private-fixtures/simulated_secret_token.txt",
            "..%2fprivate-fixtures%2fsimulated_secret_token.txt",
            "/etc/passwd",
            "C:\\Windows\\win.ini",
            "welcome.txt/../../private-fixtures/simulated_secret_token.txt"
    })
    @DisplayName("3. Chặn triệt để các biến thể payload Path Traversal")
    void shouldBlockAllPathTraversalVariants(String maliciousPayload) {
        // When & Then: Phải ném ngoại lệ bảo mật hoặc ngoại lệ định dạng không hợp lệ
        assertThatThrownBy(() -> secureFileService.loadFileAsResource(maliciousPayload))
                .isInstanceOfAny(InvalidFileRequestException.class, SecurityPathException.class);
    }

    @Test
    @DisplayName("4. Chặn tấn công Null Byte Injection")
    void shouldBlockNullByteInjection() {
        // Given
        String nullBytePayload = "welcome.txt\0.png";

        // When & Then
        assertThatThrownBy(() -> secureFileService.loadFileAsResource(nullBytePayload))
                .isInstanceOfAny(SecurityPathException.class, InvalidFileRequestException.class);
    }

    @Test
    @DisplayName("5. Tên tệp rỗng hoặc chỉ có khoảng trắng")
    void shouldRejectBlankFilename() {
        assertThatThrownBy(() -> secureFileService.loadFileAsResource("   "))
                .isInstanceOf(InvalidFileRequestException.class);
    }

    @Test
    @DisplayName("6. Tệp không tồn tại trong thư mục an toàn")
    void shouldThrowFileNotFoundForNonExistentValidFilename() {
        // Given: Tên hợp lệ theo Whitelist nhưng file không tồn tại
        String nonExistentFile = "not_found_report.txt";

        // When & Then
        assertThatThrownBy(() -> secureFileService.loadFileAsResource(nonExistentFile))
                .isInstanceOf(FileNotFoundException.class);
    }
}
