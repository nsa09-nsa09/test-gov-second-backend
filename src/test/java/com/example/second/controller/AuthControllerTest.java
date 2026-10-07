package com.example.second.controller;

import com.example.second.dto.TokenExchangeResponse;
import com.example.second.dto.UserInfoDto;
import com.example.second.service.IdTokenValidator;
import com.example.second.service.KeycloakTokenExchangeService;
import com.example.second.service.SecondTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    private MockMvc mockMvc;

    @Mock
    private IdTokenValidator idTokenValidator;

    @Mock
    private SecondTokenService secondTokenService;

    @Mock
    private KeycloakTokenExchangeService keycloakTokenExchangeService;

    @BeforeEach
    void setUp() {
        AuthController controller = new AuthController(idTokenValidator, secondTokenService, keycloakTokenExchangeService);
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new com.example.second.exception.GlobalExceptionHandler())
                .build();
    }

    @Test
    @DisplayName("POST /api/auth/exchange c валидным id_token возвращает токены Second Backend")
    void testExchangeSuccess() throws Exception {
        UserInfoDto user = new UserInfoDto("user-1", "aitu3", "aitu3@test.kz", "Aitu User", List.of("user"));
        TokenExchangeResponse response = new TokenExchangeResponse(
                "second-access-token",
                "second-refresh-token",
                "Bearer",
                900,
                604800,
                user
        );

        when(idTokenValidator.validateAndExtractUser("valid-id-token")).thenReturn(user);
        when(secondTokenService.issueTokens(user)).thenReturn(response);

        mockMvc.perform(post("/api/auth/exchange")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"id_token": "valid-id-token"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").value("second-access-token"))
                .andExpect(jsonPath("$.refresh_token").value("second-refresh-token"))
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.expires_in").value(900))
                .andExpect(jsonPath("$.user.username").value("aitu3"));
    }

    @Test
    @DisplayName("POST /api/auth/exchange с пустым токеном возвращает 400 Bad Request")
    void testExchangeEmptyToken() throws Exception {
        mockMvc.perform(post("/api/auth/exchange")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"id_token": ""}
                                """))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("POST /api/auth/refresh с валидным refresh_token возвращает новые токены")
    void testRefreshSuccess() throws Exception {
        UserInfoDto user = new UserInfoDto("user-1", "aitu3", "aitu3@test.kz", "Aitu User", List.of("user"));
        TokenExchangeResponse response = new TokenExchangeResponse(
                "new-access-token",
                "new-refresh-token",
                "Bearer",
                900,
                604800,
                user
        );

        when(secondTokenService.refresh("valid-refresh-token")).thenReturn(response);

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"refresh_token": "valid-refresh-token"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").value("new-access-token"))
                .andExpect(jsonPath("$.refresh_token").value("new-refresh-token"));
    }

    @Test
    @DisplayName("POST /api/auth/exchange-access-token с валидным access_token возвращает токены от Keycloak")
    void testExchangeAccessTokenSuccess() throws Exception {
        UserInfoDto user = new UserInfoDto("user-1", "aitu3", "aitu3@test.kz", "Aitu User", List.of("user"));
        TokenExchangeResponse response = new TokenExchangeResponse(
                "kc-access-token",
                "kc-refresh-token",
                "Bearer",
                300,
                1800,
                user
        );

        when(keycloakTokenExchangeService.exchangeAccessToken("alem-access-token")).thenReturn(response);

        mockMvc.perform(post("/api/auth/exchange-access-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"access_token": "alem-access-token"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").value("kc-access-token"))
                .andExpect(jsonPath("$.refresh_token").value("kc-refresh-token"))
                .andExpect(jsonPath("$.expires_in").value(300))
                .andExpect(jsonPath("$.user.username").value("aitu3"));
    }

    @Test
    @DisplayName("POST /api/auth/exchange-access-token с пустым токеном возвращает 400 Bad Request")
    void testExchangeAccessTokenEmpty() throws Exception {
        mockMvc.perform(post("/api/auth/exchange-access-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"access_token": ""}
                                """))
                .andExpect(status().isBadRequest());
    }
}
