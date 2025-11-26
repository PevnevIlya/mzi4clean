package com.example.AuthenticationService.dto;

public record VerifyRequest(String message, String signatureHex, String publicKeyHex) {}