package com.example.AuthenticationService.dto;

public record SignResponse(String message, String signatureHex, String publicKeyHex) {}