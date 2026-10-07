package com.example.second;

import com.example.second.dto.TokenExchangeResponse;
import com.example.second.dto.UserInfoDto;
import com.example.second.exception.AuthException;
import com.example.second.service.SecondTokenService;
import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SecondTokenServiceTest {

    private SecondTokenService tokenService;
    private final String secret = "test-secret-key-that-is-at-least-256-bits-long-for-hmac-sha256!!";

    @BeforeEach
    void setUp() {
        tokenService = new SecondTokenService(secret, "second-backend", "second-service", 900, 604800);
    }

    @Test
    @DisplayName("Успешный выпуск пары Access и Refresh токенов")
    void testIssueTokens() throws Exception {
        UserInfoDto user = new UserInfoDto(
                "user-123",
                "aitu3",
                "aitu3@example.com",
                "Aitu User",
                List.of("user", "admin")
        );

        TokenExchangeResponse response = tokenService.issueTokens(user);

        assertNotNull(response.accessToken());
        assertNotNull(response.refreshToken());
        assertEquals("Bearer", response.tokenType());
        assertEquals(900, response.expiresIn());
        assertEquals(604800, response.refreshExpiresIn());
        assertEquals("aitu3", response.user().username());

        // Проверяем Access Token
        JWTClaimsSet accessClaims = tokenService.validateToken(response.accessToken(), "access");
        assertEquals("second-backend", accessClaims.getIssuer());
        assertEquals("user-123", accessClaims.getSubject());
        assertEquals("access", accessClaims.getStringClaim("token_type"));

        // Проверяем Refresh Token
        JWTClaimsSet refreshClaims = tokenService.validateToken(response.refreshToken(), "refresh");
        assertEquals("second-backend", refreshClaims.getIssuer());
        assertEquals("user-123", refreshClaims.getSubject());
        assertEquals("refresh", refreshClaims.getStringClaim("token_type"));
    }

    @Test
    @DisplayName("Успешное обновление токенов через Refresh токен")
    void testRefreshToken() {
        UserInfoDto user = new UserInfoDto(
                "user-456",
                "aitu4",
                "aitu4@example.com",
                "Aitu 4",
                List.of("user")
        );

        TokenExchangeResponse initial = tokenService.issueTokens(user);
        TokenExchangeResponse refreshed = tokenService.refresh(initial.refreshToken());

        assertNotNull(refreshed.accessToken());
        assertNotNull(refreshed.refreshToken());
        assertNotEquals(initial.accessToken(), refreshed.accessToken());
        assertEquals("aitu4", refreshed.user().username());
    }

    @Test
    @DisplayName("Отказ при передаче Access токена вместо Refresh токена")
    void testRejectAccessTokenAsRefresh() {
        UserInfoDto user = new UserInfoDto(
                "user-789",
                "aitu5",
                "aitu5@example.com",
                "Aitu 5",
                List.of("user")
        );

        TokenExchangeResponse initial = tokenService.issueTokens(user);
        assertThrows(AuthException.class, () -> tokenService.refresh(initial.accessToken()));
    }

    @Test
    @DisplayName("Отказ при неверной подписи токена")
    void testInvalidSignature() {
        SecondTokenService anotherService = new SecondTokenService(
                "different-secret-key-that-is-at-least-256-bits-long-for-hmac-sha256!!",
                "second-backend",
                "second-service",
                900,
                604800
        );

        UserInfoDto user = new UserInfoDto("user-1", "test", "test@mail.com", "Test", List.of());
        TokenExchangeResponse response = anotherService.issueTokens(user);

        assertThrows(AuthException.class, () -> tokenService.validateToken(response.accessToken(), "access"));
    }
}
