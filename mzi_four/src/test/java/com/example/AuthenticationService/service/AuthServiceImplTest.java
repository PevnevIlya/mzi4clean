package com.example.AuthenticationService.service;

import com.example.AuthenticationService.dto.LoginRequest;
import com.example.AuthenticationService.dto.RegisterRequest;
import com.example.AuthenticationService.entity.AuthUser;
import com.example.AuthenticationService.repository.AuthUserRepository;
import com.example.AuthenticationService.service.implementation.AuthServiceImpl;
import com.example.AuthenticationService.util.JwtUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import java.util.Optional;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AuthServiceImplTest {

    private AuthUserRepository userRepository;
    private JwtUtil jwtUtil;
    private AuthServiceImpl authService;

    @BeforeEach
    void setUp() {
        userRepository = mock(AuthUserRepository.class);
        jwtUtil = mock(JwtUtil.class);
        authService = new AuthServiceImpl(userRepository, jwtUtil);
    }

    @Test
    void testRegisterSuccess() {
        RegisterRequest request = new RegisterRequest("newUser", "password");

        when(userRepository.findByUsername("newUser")).thenReturn(Optional.empty());
        when(userRepository.save(Mockito.any(AuthUser.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        var response = authService.register(request);

        assertEquals("User registered successfully", response.getMessage());
        verify(userRepository, times(1)).save(Mockito.any(AuthUser.class));
    }

    @Test
    void testRegisterUserAlreadyExists() {
        RegisterRequest request = new RegisterRequest("existingUser", "password");
        when(userRepository.findByUsername("existingUser"))
                .thenReturn(Optional.of(new AuthUser("existingUser", "hashed")));

        assertThrows(RuntimeException.class, () -> authService.register(request));
    }

    @Test
    void testLoginSuccess() {
        String rawPassword = "password";
        String hashedPassword = new BCryptPasswordEncoder().encode(rawPassword);
        AuthUser user = new AuthUser("john", hashedPassword);

        when(userRepository.findByUsername("john")).thenReturn(Optional.of(user));
        when(jwtUtil.generateAccessToken("john")).thenReturn("access123");
        when(jwtUtil.generateRefreshToken("john")).thenReturn("refresh123");

        var response = authService.login(new LoginRequest("john", rawPassword));

        assertEquals("access123", response.getAccessToken());
        assertEquals("refresh123", response.getRefreshToken());
    }

    @Test
    void testLoginInvalidPassword() {
        String hashedPassword = new BCryptPasswordEncoder().encode("correct");
        AuthUser user = new AuthUser("john", hashedPassword);

        when(userRepository.findByUsername("john")).thenReturn(Optional.of(user));

        assertThrows(RuntimeException.class,
                () -> authService.login(new LoginRequest("john", "wrong")));
    }

    @Test
    void testLoginUserNotFound() {
        when(userRepository.findByUsername("ghost")).thenReturn(Optional.empty());

        assertThrows(RuntimeException.class,
                () -> authService.login(new LoginRequest("ghost", "pwd")));
    }

    @Test
    void testRefreshValidToken() {
        when(jwtUtil.getUsernameFromToken("refreshToken")).thenReturn("john");
        when(jwtUtil.validateToken("refreshToken")).thenReturn(true);
        when(jwtUtil.generateAccessToken("john")).thenReturn("newAccess");
        when(jwtUtil.generateRefreshToken("john")).thenReturn("newRefresh");

        var response = authService.refresh("refreshToken");

        assertEquals("newAccess", response.getAccessToken());
        assertEquals("newRefresh", response.getRefreshToken());
    }

    @Test
    void testRefreshInvalidToken() {
        when(jwtUtil.validateToken("badToken")).thenReturn(false);
        when(jwtUtil.getUsernameFromToken("badToken")).thenReturn("john");

        assertThrows(RuntimeException.class,
                () -> authService.refresh("badToken"));
    }

    @Test
    void testValidateValidToken() {
        when(jwtUtil.validateToken("token123")).thenReturn(true);
        when(jwtUtil.getUsernameFromToken("token123")).thenReturn("john");

        var response = authService.validate("token123");

        assertTrue(response.isValid());
        assertEquals("john", response.getUsername());
    }

    @Test
    void testValidateInvalidToken() {
        when(jwtUtil.validateToken("bad")).thenReturn(false);

        var response = authService.validate("bad");

        assertFalse(response.isValid());
        assertNull(response.getUsername());
    }
}
