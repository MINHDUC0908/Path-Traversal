package com.securitylab.pathtraversal;

import com.securitylab.pathtraversal.config.FileStorageProperties;
import com.securitylab.pathtraversal.exception.FileNotFoundException;
import com.securitylab.pathtraversal.exception.InvalidFileRequestException;
import com.securitylab.pathtraversal.exception.SecurityPathException;
import com.securitylab.pathtraversal.service.SecureFileService;
import com.securitylab.pathtraversal.service.VulnerableFileService;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Bộ kiểm thử hồi quy (Regression Test) và các trường hợp biên của hệ thống tệp (Filesystem Edge Cases).
 * Đáp ứng đầy đủ các yêu cầu kiểm thử bảo mật nâng cao:
 * - So sánh trực tiếp hành vi giữa Vulnerable Lab và Secure Lab trên cùng một fixture.
 * - Kiểm tra xử lý đối tượng là thư mục thay vì tệp thường (Regular file vs Directory).
 * - Kiểm tra xử lý Symbolic Link trỏ ra ngoài thư mục an toàn.
 * - Xác minh chính xác nguyên nhân bị từ chối thay vì chỉ kiểm tra mã lỗi chung chung.
 */
@DisplayName("Kiểm thử Hồi quy & Các trường hợp biên Filesystem (Regression & Edge Cases)")
class PathTraversalRegressionTest {

    @TempDir
    Path tempSandbox;

    private Path uploadsDir;
    private Path privateDir;
    private Path secretFile;

    private VulnerableFileService vulnerableService;
    private SecureFileService secureService;

    @BeforeEach
    void setUp() throws IOException {
        // Chuẩn bị môi trường fixture cô lập bằng @TempDir
        uploadsDir = tempSandbox.resolve("uploads");
        privateDir = tempSandbox.resolve("private-fixtures");
        Files.createDirectories(uploadsDir);
        Files.createDirectories(privateDir);

        // Tạo tệp công khai
        Files.writeString(uploadsDir.resolve("public.txt"), "Dữ liệu công khai hợp lệ.", StandardCharsets.UTF_8);

        // Tạo tệp bí mật trong thư mục riêng
        secretFile = privateDir.resolve("secret.txt");
        Files.writeString(secretFile, "DỮ LIỆU BÍ MẬT CẦN BẢO VỆ", StandardCharsets.UTF_8);

        // Cấu hình properties trỏ vào tempSandbox
        FileStorageProperties props = new FileStorageProperties();
        props.setBaseDir(uploadsDir.toString());
        props.setSandboxRoot(tempSandbox.toString());

        this.vulnerableService = new VulnerableFileService(props);
        this.secureService = new SecureFileService(props);
    }

    @Test
    @DisplayName("REGRESSION-01: Đối chiếu trực tiếp kết quả trước và sau khi vá lỗi với payload '../'")
    void compareVulnerableAndSecureOnSamePayload() throws IOException {
        String attackPayload = "../private-fixtures/secret.txt";

        // 1. Kiểm thử trên phiên bản CÓ LỖ HỔNG:
        // Kết quả mong đợi: Lỗ hổng bị khai thác, đọc trộm được nội dung tệp secret.txt
        Resource vulnResource = vulnerableService.loadFileAsResource(attackPayload);
        assertThat(vulnResource.exists()).isTrue();
        assertThat(vulnResource.getContentAsString(StandardCharsets.UTF_8))
                .isEqualTo("DỮ LIỆU BÍ MẬT CẦN BẢO VỆ");

        // 2. Kiểm thử trên phiên bản ĐÃ VÁ LỖ HỔNG (Secure):
        // Kết quả mong đợi: Bản vá chặn đứng truy cập, ném InvalidFileRequestException hoặc SecurityPathException
        assertThatThrownBy(() -> secureService.loadFileAsResource(attackPayload))
                .isInstanceOfAny(InvalidFileRequestException.class, SecurityPathException.class)
                .hasMessageContaining("không hợp lệ");
    }

    @Test
    @DisplayName("EDGE-CASE-02: Yêu cầu truy cập một thư mục thay vì tệp thường (Directory vs Regular File)")
    void shouldRejectDirectoryAccess() throws IOException {
        // Tạo một thư mục con bên trong uploads
        Path subDir = uploadsDir.resolve("subfolder");
        Files.createDirectories(subDir);

        // Khi yêu cầu tải 'subfolder'
        assertThatThrownBy(() -> secureService.loadFileAsResource("subfolder"))
                .isInstanceOf(FileNotFoundException.class)
                .hasMessageContaining("không phải là tệp tin hợp lệ");
    }

    @Test
    @DisplayName("EDGE-CASE-03: Xử lý an toàn Symbolic Link trỏ ra ngoài thư mục cho phép")
    void shouldSafelyHandleSymbolicLinkEscapingBaseDir() {
        // Cố gắng tạo một Symbolic Link bên trong uploads trỏ tới secretFile bên ngoài
        Path symlink = uploadsDir.resolve("link-secret.txt");
        try {
            Files.createSymbolicLink(symlink, secretFile);
        } catch (UnsupportedOperationException | IOException e) {
            // Trên Windows không có quyền Developer Mode hoặc Administrator, việc tạo symlink có thể bị OS hạn chế.
            // Bỏ qua bài test nếu OS hiện tại không cho phép tiến trình tạo symlink.
            Assumptions.abort("Hệ điều hành hiện tại không cấp quyền tạo Symbolic Link cho tiến trình non-admin: " + e.getMessage());
        }

        // Khi symlink được tạo thành công, tiến hành kiểm tra:
        // Mặc dù tên tệp 'link-secret.txt' vượt qua Whitelist regex,
        // nhưng toRealPath() và startsWith() PHẢI phát hiện đích đến thực tế nằm ở private-fixtures và CHẶN LẠI!
        assertThatThrownBy(() -> secureService.loadFileAsResource("link-secret.txt"))
                .isInstanceOf(SecurityPathException.class)
                .hasMessageContaining("Truy cập bị từ chối: Đường dẫn nằm ngoài thư mục cho phép.");
    }
}
