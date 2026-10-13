package com.securitylab.pathtraversal.exception;

/**
 * Ngoại lệ ném ra khi tệp tin hợp lệ không tồn tại trên hệ thống lưu trữ.
 */
public class FileNotFoundException extends RuntimeException {

    public FileNotFoundException(String message) {
        super(message);
    }
}
