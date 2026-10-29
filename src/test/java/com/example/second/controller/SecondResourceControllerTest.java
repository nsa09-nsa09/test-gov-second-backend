package com.example.second.controller;

import com.example.second.dto.UserInfoDto;
import com.example.second.service.KeycloakJwksService;
import com.example.second.service.KeycloakTokenValidator;
import com.example.second.service.SecondTokenService;
import com.example.second.support.TestTokens;
import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.Date;
import java.util.List;

import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class SecondResourceControllerTest {

    private MockMvc mockMvc;

    @Mock
    private SecondTokenService secondTokenService;

    @Mock
    private KeycloakJwksService jwksService;

    @BeforeEach
    void setUp() {
        lenient().when(jwksService.getKeyByKeyId(TestTokens.KID)).thenReturn(TestTokens.KEY.toPublicJWK());
        KeycloakTokenValidator validator = new KeycloakTokenValidator(jwksService, TestTokens.ISSUER);
        SecondResourceController controller = new SecondResourceController(secondTokenService, validator, "second-backend");
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new com.example.second.exception.GlobalExceptionHandler())
                .build();
    }

    @Test
    @DisplayName("GET /api/second/me с валидным HS256 токеном second возвращает 200 OK")
    void testGetMeLegacySuccess() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("second-backend")
                .audience("second-service")
                .subject("user-1")
                .expirationTime(new Date(System.currentTimeMillis() + 60000))
                .build();

        UserInfoDto user = new UserInfoDto("user-1", "aitu3", "aitu3@test.kz", "Aitu User", List.of("user"));

        when(secondTokenService.validateToken("valid-token", "access")).thenReturn(claims);
        when(secondTokenService.extractUser(claims)).thenReturn(user);

        mockMvc.perform(get("/api/second/me")
                        .header("Authorization", "Bearer valid-token"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.token_kind").value("second-legacy"))
                .andExpect(jsonPath("$.data.user.username").value("aitu3"))
                .andExpect(jsonPath("$.data.service").value("second-backend"));
    }

    @Test
    @DisplayName("GET /api/second/me с обменянным Keycloak токеном (azp=second-backend) → 200")
    void testGetMeKeycloakExchanged() throws Exception {
        mockMvc.perform(get("/api/second/me")
                        .header("Authorization", "Bearer " + TestTokens.secondToken()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.token_kind").value("keycloak"))
                .andExpect(jsonPath("$.data.azp").value("second-backend"))
                .andExpect(jsonPath("$.data.issuer").value(TestTokens.ISSUER))
                .andExpect(jsonPath("$.data.user.username").value("aitu3"));
    }

    @Test
    @DisplayName("GET /api/second/me с токеном alem (azp=test-app) → 401")
    void testGetMeAlemTokenRejected() throws Exception {
        mockMvc.perform(get("/api/second/me")
                        .header("Authorization", "Bearer " + TestTokens.alemToken()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.containsString("azp='test-app'")));
    }

    @Test
    @DisplayName("GET /api/second/me без заголовка Authorization возвращает 401")
    void testGetMeWithoutAuthHeader() throws Exception {
        mockMvc.perform(get("/api/second/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("GET /api/second/token-info для токена alem: accepted_by_me=false, провал authorized_party")
    void testTokenInfoAlem() throws Exception {
        mockMvc.perform(get("/api/second/token-info")
                        .header("Authorization", "Bearer " + TestTokens.alemToken()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.kind").value("keycloak"))
                .andExpect(jsonPath("$.alg").value("RS256"))
                .andExpect(jsonPath("$.claims.azp").value("test-app"))
                .andExpect(jsonPath("$.accepted_by_me").value(false))
                .andExpect(jsonPath("$.checks[4].name").value("authorized_party"))
                .andExpect(jsonPath("$.checks[4].passed").value(false));
    }

    @Test
    @DisplayName("GET /api/second/token-info для обменянного токена: accepted_by_me=true")
    void testTokenInfoExchanged() throws Exception {
        mockMvc.perform(get("/api/second/token-info")
                        .header("Authorization", "Bearer " + TestTokens.secondToken()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accepted_by_me").value(true))
                .andExpect(jsonPath("$.claims.azp").value("second-backend"));
    }

    @Test
    @DisplayName("GET /api/second/token-info с мусором: 200 и провал format")
    void testTokenInfoGarbage() throws Exception {
        mockMvc.perform(get("/api/second/token-info")
                        .header("Authorization", "Bearer garbage"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accepted_by_me").value(false))
                .andExpect(jsonPath("$.checks[0].name").value("format"));
    }
}
