package com.example.AuthenticationService.entity;

public class EncryptResponse {
    private String cipher; // base64

    public EncryptResponse(String cipher) { this.cipher = cipher; }
    public String getCipher() { return cipher; }
    public void setCipher(String cipher) { this.cipher = cipher; }
}
