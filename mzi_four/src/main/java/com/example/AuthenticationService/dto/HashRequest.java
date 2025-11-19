package com.example.AuthenticationService.dto;

import jakarta.validation.constraints.NotBlank;

public record HashRequest(
        String text
        //record чтобы без геттеров
) {}
