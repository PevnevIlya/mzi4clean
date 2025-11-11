package com.example.AuthenticationService.dto;

public class StatsDto {
    private long encryptBytes;
    private long decryptBytes;

    public StatsDto(long encryptBytes, long decryptBytes) {
        this.encryptBytes = encryptBytes;
        this.decryptBytes = decryptBytes;
    }

    public long getEncryptBytes() { return encryptBytes; }
    public long getDecryptBytes() { return decryptBytes; }
    public void setEncryptBytes(long encryptBytes) { this.encryptBytes = encryptBytes; }
    public void setDecryptBytes(long decryptBytes) { this.decryptBytes = decryptBytes; }
}
