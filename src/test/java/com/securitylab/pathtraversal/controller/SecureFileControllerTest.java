package com.securitylab.pathtraversal.controller;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration Test cho SecureFileController.
 * Mục đích:
 * Kiểm chứng rằng phiên bản an toàn từ chối 100% các cuộc tấn công Path Traversal ở tầng HTTP,
 * đồng thời phân biệt rõ giữa lỗi định dạng (400 Bad Request), vi phạm bảo mật (403 Forbidden),
 * và tệp không tồn tại (404 Not Found).
 */
@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("Integration Test: SecureFileController (Tầng HTTP)")
class SecureFileControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("HTTP-SEC-01: Tải tệp hợp lệ qua query parameter (HTTP 200 OK)")
    void shouldReturn200ForLegitimateFile() throws Exception {
        mockMvc.perform(get("/api/lab/secure/files/download")
                        .param("filename", "welcome.txt"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_PLAIN))
                .andExpect(content().string(containsString("Xin chào! Đây là tệp tin công khai")));
    }

    @ParameterizedTest(name = "Kịch bản chặn HTTP: {0}")
    @ValueSource(strings = {
            "../private-fixtures/simulated_secret_token.txt",
            "..\\private-fixtures\\simulated_secret_token.txt",
            "....//private-fixtures/simulated_secret_token.txt",
            "/etc/passwd",
            "C:\\Windows\\win.ini"
    })
    @DisplayName("HTTP-SEC-02: Chặn đứng các biến thể Path Traversal với HTTP 400 Bad Request")
    void shouldBlockAllTraversalPayloadsWith400(String payload) throws Exception {
        mockMvc.perform(get("/api/lab/secure/files/download")
                        .param("filename", payload))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.message").value(containsString("Tên tệp không hợp lệ")));
    }

    @Test
    @DisplayName("HTTP-SEC-03: Tên tệp hợp lệ về cú pháp nhưng không tồn tại (HTTP 404 Not Found)")
    void shouldReturn404ForNonExistentFile() throws Exception {
        mockMvc.perform(get("/api/lab/secure/files/download")
                        .param("filename", "not_found_report.txt"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404))
                .andExpect(jsonPath("$.error").value("Not Found"))
                .andExpect(jsonPath("$.message").value(containsString("không tồn tại")));
    }

    @Test
    @DisplayName("HTTP-SEC-04: Tên tệp rỗng hoặc chỉ có khoảng trắng (HTTP 400 Bad Request)")
    void shouldReturn400ForBlankFilename() throws Exception {
        mockMvc.perform(get("/api/lab/secure/files/download")
                        .param("filename", "   "))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400));
    }

    @Test
    @DisplayName("HTTP-SEC-05: Tải tệp hợp lệ qua Path Variable wildcard (HTTP 200 OK)")
    void shouldReturn200ViaPathVariable() throws Exception {
        mockMvc.perform(get("/api/lab/secure/files/view/welcome.txt"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Xin chào! Đây là tệp tin công khai")));
    }
}
