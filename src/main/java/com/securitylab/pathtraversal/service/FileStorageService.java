package com.securitylab.pathtraversal.service;

import org.springframework.core.io.Resource;

/**
 * Interface định nghĩa các hoạt động thao tác tệp tin.
 * Cả VulnerableFileService và SecureFileService đều triển khai interface này
 * để đảm bảo tính nhất quán về mặt hợp đồng nghiệp vụ (Interface Segregation).
 */
public interface FileStorageService {

    /**
     * Tải tệp tin dưới dạng Spring Resource để phục vụ download/stream qua HTTP.
     *
     * @param filename Tên hoặc đường dẫn tệp do client cung cấp
     * @return Đối tượng Resource đại diện cho tệp tin
     */
    Resource loadFileAsResource(String filename);
}
