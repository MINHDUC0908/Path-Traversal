package com.securitylab.pathtraversal.controller;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration Test cho VulnerableFileController.
 * Mục đích:
 * Kiểm chứng hành vi của API Vulnerable ở tầng HTTP:
 * 1. Đọc tệp hợp lệ trả về HTTP 200 và nội dung tệp.
 * 2. Tấn công Path Traversal lọt qua và trả về HTTP 200 cùng nội dung nhạy cảm giả lập (Minh họa lỗ hổng).
 * 3. Tấn công vượt ra ngoài phạm vi Lab Sandbox bị chặn với HTTP 403 Forbidden.
 * 4. Tệp không tồn tại trả về HTTP 404 Not Found.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("lab")
@DisplayName("Integration Test: VulnerableFileController (Tầng HTTP)")
class VulnerableFileControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("HTTP-VULN-01: Tải tệp hợp lệ qua query parameter (HTTP 200)")
    void shouldReturn200ForLegitimateFile() throws Exception {
        mockMvc.perform(get("/api/lab/vulnerable/files/download")
                        .param("filename", "welcome.txt"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_PLAIN))
                .andExpect(content().string(containsString("Xin chào! Đây là tệp tin công khai hợp lệ")));
    }

    @Test
    @DisplayName("HTTP-VULN-02: Khai thác Path Traversal thành công qua HTTP (HTTP 200 - Lỗ hổng CWE-22)")
    void shouldSucceedPathTraversalAttackOverHttp() throws Exception {
        // Kẻ tấn công gửi payload qua tham số filename
        mockMvc.perform(get("/api/lab/vulnerable/files/download")
                        .param("filename", "../private-fixtures/simulated_secret_token.txt"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("SECRET_KEY=simulated_jwt_secret_xyz789")));
    }

    @Test
    @DisplayName("HTTP-VULN-03: Chặn tấn công thoát ra ngoài Lab Sandbox (HTTP 403 Forbidden)")
    void shouldReturn403WhenEscapingEntireSandbox() throws Exception {
        // Cố gắng đọc tệp hệ điều hành ngoài thư mục lab-sandbox
        mockMvc.perform(get("/api/lab/vulnerable/files/download")
                        .param("filename", "../../../../Windows/win.ini"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value(403))
                .andExpect(jsonPath("$.error").value("Forbidden"))
                .andExpect(jsonPath("$.message").value(containsString("vi phạm chính sách bảo mật")));
    }

    @Test
    @DisplayName("HTTP-VULN-04: Tệp không tồn tại trả về HTTP 404 Not Found")
    void shouldReturn404WhenFileDoesNotExist() throws Exception {
        mockMvc.perform(get("/api/lab/vulnerable/files/download")
                        .param("filename", "non_existing_file.txt"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404))
                .andExpect(jsonPath("$.error").value("Not Found"));
    }

    @Test
    @DisplayName("HTTP-VULN-05: Tải tệp hợp lệ qua Path Variable wildcard (HTTP 200)")
    void shouldReturn200ViaPathVariable() throws Exception {
        mockMvc.perform(get("/api/lab/vulnerable/files/view/welcome.txt"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Xin chào! Đây là tệp tin công khai")));
    }
}
