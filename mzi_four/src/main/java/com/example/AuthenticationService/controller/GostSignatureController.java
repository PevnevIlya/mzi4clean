package com.example.AuthenticationService.controller;

import com.example.AuthenticationService.dto.*;
import com.example.AuthenticationService.service.GostSignatureService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/gost")
@CrossOrigin
public class GostSignatureController {

    private final GostSignatureService service;

    public GostSignatureController(GostSignatureService service) {
        this.service = service;
    }

    @GetMapping("/keys")
    public ResponseEntity<?> generateKeys() throws Exception {
        service.generateKeyPair();
        return ResponseEntity.ok(new SignResponse("Keys generated", null, service.getPublicKeyHex()));
    }

    @PostMapping("/sign")
    public ResponseEntity<SignResponse> sign(@RequestBody SignRequest req) throws Exception {
        String signature = service.sign(req.message());
        return ResponseEntity.ok(new SignResponse("Signed", signature, service.getPublicKeyHex()));
    }

    @PostMapping("/verify")
    public ResponseEntity<VerifyResponse> verify(@RequestBody VerifyRequest req) throws Exception {
        boolean valid = service.verify(req.message(), req.signatureHex(), req.publicKeyHex());
        return ResponseEntity.ok(new VerifyResponse(valid, valid ? "Valid" : "Invalid"));
    }
}