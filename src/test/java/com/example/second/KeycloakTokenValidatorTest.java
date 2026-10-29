package com.example.second;

import com.example.second.exception.AuthException;
import com.example.second.service.KeycloakJwksService;
import com.example.second.service.KeycloakTokenValidator;
import com.example.second.support.TestTokens;
import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.HttpStatus;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

class KeycloakTokenValidatorTest {

    private KeycloakTokenValidator validator;

    @BeforeEach
    void setUp() {
        KeycloakJwksService jwksService = Mockito.mock(KeycloakJwksService.class);
        when(jwksService.getKeyByKeyId(TestTokens.KID)).thenReturn(TestTokens.KEY.toPublicJWK());
        validator = new KeycloakTokenValidator(jwksService, TestTokens.ISSUER);
    }

    @Test
    @DisplayName("Токен с azp=second-backend проходит все проверки")
    void acceptsSecondBackendToken() {
        JWTClaimsSet claims = validator.validate(TestTokens.secondToken(), "second-backend");
        assertEquals("second-backend", claims.getClaim("azp"));
    }

    @Test
    @DisplayName("Токен alem (azp=test-app) отклоняется проверкой authorized_party")
    void rejectsAlemTokenForSecond() {
        AuthException ex = assertThrows(AuthException.class,
                () -> validator.validate(TestTokens.alemToken(), "second-backend"));
        assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatus());
        assertTrue(ex.getMessage().contains("authorized_party"));
        assertTrue(ex.getMessage().contains("test-app"));
    }

    @Test
    @DisplayName("Без требования azp токен alem валиден (используется для subject_token)")
    void alemTokenValidWithoutAzpRequirement() {
        assertNotNull(validator.validate(TestTokens.alemToken(), null));
    }

    @Test
    @DisplayName("Чужой issuer отклоняется")
    void rejectsForeignIssuer() {
        String token = TestTokens.sign(TestTokens.claims("second-backend", List.of("account"))
                .issuer("http://evil/realms/GovApps").build(), TestTokens.KEY);
        AuthException ex = assertThrows(AuthException.class, () -> validator.validate(token, "second-backend"));
        assertTrue(ex.getMessage().contains("issuer"));
    }

    @Test
    @DisplayName("Истёкший токен отклоняется")
    void rejectsExpiredToken() {
        String token = TestTokens.sign(TestTokens.claims("second-backend", List.of("account"))
                .expirationTime(new Date(System.currentTimeMillis() - 1000)).build(), TestTokens.KEY);
        AuthException ex = assertThrows(AuthException.class, () -> validator.validate(token, "second-backend"));
        assertTrue(ex.getMessage().contains("expiration"));
    }

    @Test
    @DisplayName("Подпись чужим ключом отклоняется")
    void rejectsWrongSignature() {
        String token = TestTokens.sign(TestTokens.claims("second-backend", List.of("account")).build(), TestTokens.OTHER_KEY);
        AuthException ex = assertThrows(AuthException.class, () -> validator.validate(token, "second-backend"));
        assertTrue(ex.getMessage().contains("signature"));
    }

    @Test
    @DisplayName("inspect возвращает все проверки, не прерываясь на первой ошибке")
    void inspectReportsAllChecks() {
        String token = TestTokens.sign(TestTokens.claims("test-app", List.of("account"))
                .expirationTime(new Date(System.currentTimeMillis() - 1000)).build(), TestTokens.KEY);

        KeycloakTokenValidator.ValidationReport report = validator.inspect(token, "second-backend");

        assertFalse(report.passed());
        assertEquals(5, report.checks().size());
        assertEquals("expiration", report.firstFailure().name());
        assertFalse(report.checks().get(4).passed());
    }

    @Test
    @DisplayName("Мусор вместо JWT: провал проверки format")
    void inspectGarbage() {
        KeycloakTokenValidator.ValidationReport report = validator.inspect("not-a-jwt", "second-backend");
        assertFalse(report.passed());
        assertEquals("format", report.firstFailure().name());
        assertNull(report.claims());
    }
}
