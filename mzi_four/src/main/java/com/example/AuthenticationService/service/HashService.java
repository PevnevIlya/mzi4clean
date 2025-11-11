package com.example.AuthenticationService.service;

import com.example.AuthenticationService.dto.HashResponse;
import com.example.AuthenticationService.util.GOST3411_2012;
import com.example.AuthenticationService.util.SHA1;
import org.springframework.stereotype.Service;

@Service
public class HashService {

    public HashResponse computeHashes(String text) {
        byte[] data = text.getBytes(java.nio.charset.StandardCharsets.UTF_8);

        String gost512 = GOST3411_2012.hash512(data);
        String gost256 = GOST3411_2012.hash256(data);
        String sha1    = SHA1.hash(data);

        return new HashResponse(gost512, gost256, sha1);
    }
}
