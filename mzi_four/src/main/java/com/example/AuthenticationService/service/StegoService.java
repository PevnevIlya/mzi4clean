package com.example.AuthenticationService.service;

import org.springframework.web.multipart.MultipartFile;

public interface StegoService {
    byte[] hide(MultipartFile image, String message) throws Exception;
    String extract(MultipartFile image) throws Exception;
}
