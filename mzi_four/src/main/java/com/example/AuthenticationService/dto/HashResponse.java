package com.example.AuthenticationService.dto;

public record HashResponse(
        String gost512,
        String gost256,
        String sha1
) {}
