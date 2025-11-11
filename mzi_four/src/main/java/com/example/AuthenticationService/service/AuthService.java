package com.example.AuthenticationService.service;

import com.example.AuthenticationService.dto.LoginRequest;
import com.example.AuthenticationService.dto.LoginResponse;
import com.example.AuthenticationService.dto.RegisterRequest;
import com.example.AuthenticationService.dto.RegisterResponse;
import com.example.AuthenticationService.dto.ValidateTokenResponse;

public interface AuthService {
    RegisterResponse register(RegisterRequest request);
    LoginResponse login(LoginRequest request);
    LoginResponse refresh(String refreshToken);
    ValidateTokenResponse validate(String accessToken);
}
