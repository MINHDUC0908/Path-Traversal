package com.securitylab.pathtraversal.exception;

import com.securitylab.pathtraversal.dto.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Bộ xử lý ngoại lệ toàn cục (Global Exception Handler).
 * Nhiệm vụ bảo mật:
 * 1. Bắt tất cả các loại ngoại lệ, trả về mã trạng thái HTTP chính xác theo ngữ cảnh.
 * 2. Ngăn chặn tuyệt đối việc rò rỉ stack trace hoặc đường dẫn filesystem thực của server ra ngoài.
 * 3. Ghi log an toàn nội bộ để phục vụ điều tra (Audit & Incident Response).
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(SecurityPathException.class)
    public ResponseEntity<ErrorResponse> handleSecurityPathException(
            SecurityPathException ex,
            HttpServletRequest request
    ) {
        // Ghi log cảnh báo mức WARN/SECURITY về nỗ lực vi phạm ranh giới
        log.warn("Security Alert: Phát hiện nỗ lực Path Traversal tại URI [{}]. Lý do: {}",
                request.getRequestURI(), ex.getMessage());

        ErrorResponse response = new ErrorResponse(
                HttpStatus.FORBIDDEN.value(),
                "Forbidden",
                "Truy cập bị từ chối: Đường dẫn yêu cầu vi phạm chính sách bảo mật hệ thống.",
                request.getRequestURI()
        );
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
    }

    @ExceptionHandler(FileNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleFileNotFoundException(
            FileNotFoundException ex,
            HttpServletRequest request
    ) {
        log.info("File not found tại URI [{}]: {}", request.getRequestURI(), ex.getMessage());

        ErrorResponse response = new ErrorResponse(
                HttpStatus.NOT_FOUND.value(),
                "Not Found",
                "Tệp tin yêu cầu không tồn tại trong thư mục lưu trữ.",
                request.getRequestURI()
        );
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
    }

    @ExceptionHandler(InvalidFileRequestException.class)
    public ResponseEntity<ErrorResponse> handleInvalidFileRequestException(
            InvalidFileRequestException ex,
            HttpServletRequest request
    ) {
        log.warn("Invalid file request tại URI [{}]: {}", request.getRequestURI(), ex.getMessage());

        ErrorResponse response = new ErrorResponse(
                HttpStatus.BAD_REQUEST.value(),
                "Bad Request",
                ex.getMessage(),
                request.getRequestURI()
        );
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGenericException(
            Exception ex,
            HttpServletRequest request
    ) {
        log.error("Internal server error tại URI [{}]", request.getRequestURI(), ex);

        ErrorResponse response = new ErrorResponse(
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                "Internal Server Error",
                "Đã xảy ra lỗi nội bộ máy chủ. Vui lòng thử lại sau.",
                request.getRequestURI()
        );
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }
}
