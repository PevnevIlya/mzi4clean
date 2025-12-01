package com.example.AuthenticationService.controller;

import com.example.AuthenticationService.dto.*;
import com.example.AuthenticationService.service.EciesService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/ecies")
@CrossOrigin
public class EciesController {

    private final EciesService service;

    public EciesController(EciesService service) {
        this.service = service;
    }

    @GetMapping("/keys")
    public ResponseEntity<KeyResponse> generateKeys() throws Exception {
        service.generateKeys();
        return ResponseEntity.ok(new KeyResponse(service.getPublicKeyHex()));
    }

    @PostMapping("/encrypt")
    public ResponseEntity<EncryptResponse> encrypt(@RequestBody EncryptRequest request) throws Exception {
        String encrypted = service.encrypt(request.message(), request.publicKeyHex());
        return ResponseEntity.ok(new EncryptResponse(encrypted));
    }

    @PostMapping("/decrypt")
    public ResponseEntity<DecryptResponse> decrypt(@RequestBody DecryptRequest request) throws Exception {
        String decrypted = service.decrypt(request.encryptedHex());
        return ResponseEntity.ok(new DecryptResponse(decrypted));
    }
}