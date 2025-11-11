package com.example.AuthenticationService.controller;

import com.example.AuthenticationService.entity.DecryptRequest;
import com.example.AuthenticationService.entity.DecryptResponse;
import com.example.AuthenticationService.entity.EncryptRequest;
import com.example.AuthenticationService.entity.EncryptResponse;
import com.example.AuthenticationService.service.McElieceService;
import com.example.AuthenticationService.service.StatsService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class McElieceController {

    private final McElieceService mService;
    private final StatsService stats;

    public McElieceController(McElieceService mService, StatsService stats) {
        this.mService = mService;
        this.stats = stats;
    }

    @PostMapping("/encrypt")
    public ResponseEntity<EncryptResponse> encrypt(@RequestBody EncryptRequest request,
                                                   @RequestHeader(value = "Authorization", required = false) String auth) {
        String cipher = mService.encryptText(request.getText());
        int bytes = mService.estimateCipherBytesForText(request.getText());
        stats.addEncryptBytes(bytes);
        return ResponseEntity.ok(new EncryptResponse(cipher));
    }

    @PostMapping("/decrypt")
    public ResponseEntity<DecryptResponse> decrypt(@RequestBody DecryptRequest request,
                                                   @RequestHeader(value = "Authorization", required = false) String auth) {
        String text = mService.decryptCipher(request.getCipher());
        int plainBytes = mService.estimatePlainBytesFromCipherBase64(request.getCipher());
        stats.addDecryptBytes(plainBytes);
        return ResponseEntity.ok(new DecryptResponse(text));
    }
}
