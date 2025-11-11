package com.example.AuthenticationService.service.implementation;

import com.example.AuthenticationService.dto.LoginRequest;
import com.example.AuthenticationService.dto.LoginResponse;
import com.example.AuthenticationService.dto.RegisterRequest;
import com.example.AuthenticationService.dto.RegisterResponse;
import com.example.AuthenticationService.dto.ValidateTokenResponse;
import com.example.AuthenticationService.entity.AuthUser;
import com.example.AuthenticationService.repository.AuthUserRepository;
import com.example.AuthenticationService.service.AuthService;
import com.example.AuthenticationService.util.JwtUtil;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthServiceImpl implements AuthService {

    private final AuthUserRepository userRepository;
    private final JwtUtil jwtUtil;
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public AuthServiceImpl(AuthUserRepository userRepository, JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.jwtUtil = jwtUtil;
    }

    @Override
    public RegisterResponse register(RegisterRequest request) {
        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            throw new RuntimeException("User already exists");
        }
        AuthUser user = new AuthUser(request.getUsername(), passwordEncoder.encode(request.getPassword()));
        userRepository.save(user);
        return new RegisterResponse("User registered successfully");
    }

    @Override
    public LoginResponse login(LoginRequest request) {
        AuthUser user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new RuntimeException("Invalid username or password"));

        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            throw new RuntimeException("Invalid username or password");
        }

        String accessToken = jwtUtil.generateAccessToken(user.getUsername());
        String refreshToken = jwtUtil.generateRefreshToken(user.getUsername());

        return new LoginResponse(accessToken, refreshToken);
    }

    @Override
    public LoginResponse refresh(String refreshToken) {
        String username = jwtUtil.getUsernameFromToken(refreshToken);
        if (!jwtUtil.validateToken(refreshToken)) {
            throw new RuntimeException("Invalid refresh token");
        }

        String newAccess = jwtUtil.generateAccessToken(username);
        String newRefresh = jwtUtil.generateRefreshToken(username);
        return new LoginResponse(newAccess, newRefresh);
    }

    @Override
    public ValidateTokenResponse validate(String accessToken) {
        boolean valid = jwtUtil.validateToken(accessToken);
        String username = valid ? jwtUtil.getUsernameFromToken(accessToken) : null;
        return new ValidateTokenResponse(valid, username);
    }
}
