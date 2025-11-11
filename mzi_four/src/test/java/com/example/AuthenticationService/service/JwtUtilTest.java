package com.example.AuthenticationService.service;

import com.example.AuthenticationService.util.JwtUtil;
import org.junit.jupiter.api.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

class JwtUtilTest {

    private final JwtUtil jwtUtil = new JwtUtil();

    @Test
    void testGenerateAndValidateAccessToken() {
        String token = jwtUtil.generateAccessToken("testUser");

        assertNotNull(token);
        assertTrue(jwtUtil.validateToken(token));
        assertEquals("testUser", jwtUtil.getUsernameFromToken(token));
    }

    @Test
    void testGenerateAndValidateRefreshToken() {
        String token = jwtUtil.generateRefreshToken("otherUser");

        assertNotNull(token);
        assertTrue(jwtUtil.validateToken(token));
        assertEquals("otherUser", jwtUtil.getUsernameFromToken(token));
    }

    @Test
    void testInvalidToken_shouldThrowException() {
        String invalid = "this.is.not.a.token";

        assertFalse(jwtUtil.validateToken(invalid));
        assertThrows(Exception.class, () -> jwtUtil.getUsernameFromToken(invalid));
    }
}
