package com.example.AuthenticationService.controller;

import com.example.AuthenticationService.dto.HashRequest;
import com.example.AuthenticationService.dto.HashResponse;
import com.example.AuthenticationService.service.HashService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class HashController {

    private final HashService hashService;

    public HashController(HashService hashService) {
        this.hashService = hashService;
    }

    @PostMapping("/compute")
    public ResponseEntity<HashResponse> computeHashes(@Valid @RequestBody HashRequest request,
                                                      @RequestHeader(value = "Authorization", required = false) String auth) {
        HashResponse response = hashService.computeHashes(request.text());
        return ResponseEntity.ok(response);
    }
}
