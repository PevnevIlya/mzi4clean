package com.example.AuthenticationService.integration;

import com.example.AuthenticationService.AuthenticationServiceApplication;
import com.example.AuthenticationService.dto.LoginRequest;
import com.example.AuthenticationService.dto.LoginResponse;
import com.example.AuthenticationService.dto.RegisterRequest;
import com.example.AuthenticationService.dto.RegisterResponse;
import com.example.AuthenticationService.dto.ValidateTokenResponse;
import com.example.AuthenticationService.repository.AuthUserRepository;
import com.example.AuthenticationService.service.AuthService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

@SpringBootTest(classes = AuthenticationServiceApplication.class)
@Testcontainers
@ActiveProfiles("test")
class AuthServiceIntegrationTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:15")
            .withDatabaseName("testdb")
            .withUsername("test")
            .withPassword("test");

    @Autowired
    private AuthService authService;

    @Autowired
    private AuthUserRepository userRepository;

    @DynamicPropertySource
    static void overrideProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
    }

    @Test
    void registerLoginAndValidateUser() {
        // --- Register user ---
        RegisterRequest registerRequest = new RegisterRequest("alice", "password123");
        RegisterResponse registerResponse = authService.register(registerRequest);
        assertEquals("User registered successfully", registerResponse.getMessage());
        assertTrue(userRepository.findByUsername("alice").isPresent());

        // --- Login user ---
        LoginRequest loginRequest = new LoginRequest("alice", "password123");
        LoginResponse loginResponse = authService.login(loginRequest);
        assertNotNull(loginResponse.getAccessToken());
        assertNotNull(loginResponse.getRefreshToken());

        // --- Validate token ---
        ValidateTokenResponse validateResponse = authService.validate(loginResponse.getAccessToken());
        assertTrue(validateResponse.isValid());
        assertEquals("alice", validateResponse.getUsername());
    }

    @Test
    void refreshTokenShouldGenerateNewTokens() {
        // --- Register and login ---
        RegisterRequest registerRequest = new RegisterRequest("bob", "mypassword");
        authService.register(registerRequest);

        LoginRequest loginRequest = new LoginRequest("bob", "mypassword");
        LoginResponse loginResponse = authService.login(loginRequest);

        // --- Refresh ---
        LoginResponse refreshed = authService.refresh(loginResponse.getRefreshToken());
        assertNotNull(refreshed.getAccessToken());
        assertNotNull(refreshed.getRefreshToken());
        assertNotEquals(loginResponse.getAccessToken(), refreshed.getAccessToken());
    }
}