package com.securitylab.pathtraversal;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * Điểm khởi chạy chính của ứng dụng mô phỏng phòng lab Path Traversal.
 */
@SpringBootApplication
@ConfigurationPropertiesScan
public class PathTraversalLabApplication {

    public static void main(String[] args) {
        SpringApplication.run(PathTraversalLabApplication.class, args);
    }
}
