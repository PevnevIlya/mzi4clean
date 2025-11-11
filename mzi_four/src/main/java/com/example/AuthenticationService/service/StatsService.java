package com.example.AuthenticationService.service;

import org.springframework.stereotype.Service;

import java.util.concurrent.atomic.AtomicLong;

@Service
public class StatsService {
    private final AtomicLong encryptBytes = new AtomicLong(0);
    private final AtomicLong decryptBytes = new AtomicLong(0);

    public void addEncryptBytes(long bytes) { encryptBytes.addAndGet(bytes); }
    public void addDecryptBytes(long bytes) { decryptBytes.addAndGet(bytes); }
    public long getEncryptBytes() { return encryptBytes.get(); }
    public long getDecryptBytes() { return decryptBytes.get(); }
}
