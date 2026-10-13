package com.securitylab.pathtraversal.exception;

/**
 * Ngoại lệ ném ra khi tên tệp hoặc định dạng đầu vào không hợp lệ
 * (rỗng, chứa ký tự null byte, hoặc không khớp regex whitelist).
 */
public class InvalidFileRequestException extends RuntimeException {

    public InvalidFileRequestException(String message) {
        super(message);
    }
}
