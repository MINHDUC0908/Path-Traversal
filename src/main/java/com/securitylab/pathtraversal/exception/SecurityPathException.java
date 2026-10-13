package com.securitylab.pathtraversal.exception;

/**
 * Ngoại lệ được kích hoạt khi phát hiện hành vi truy cập vi phạm ranh giới bảo mật
 * (ví dụ: Path Traversal, symlink trỏ ra ngoài thư mục an toàn, escape jail).
 */
public class SecurityPathException extends RuntimeException {

    public SecurityPathException(String message) {
        super(message);
    }
}
