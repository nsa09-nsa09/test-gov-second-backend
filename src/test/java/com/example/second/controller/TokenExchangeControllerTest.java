package com.example.second.controller;

import com.example.second.dto.ExchangeDetailsDto;
import com.example.second.dto.IntrospectionResponse;
import com.example.second.dto.KeycloakTokenResponse;
import com.example.second.dto.TokenSummaryDto;
import com.example.second.dto.UserInfoDto;
import com.example.second.exception.AuthException;
import com.example.second.service.KeycloakTokenExchangeService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class TokenExchangeControllerTest {

    private MockMvc mockMvc;

    @Mock
    private KeycloakTokenExchangeService exchangeService;

    private final KeycloakTokenResponse response = new KeycloakTokenResponse(
            "new-access", null, "Bearer", 300, 0, "urn:ietf:params:oauth:token-type:access_token", "profile",
            new UserInfoDto("user-1", "aitu3", null, null, List.of("user")),
            new ExchangeDetailsDto(
                    new TokenSummaryDto("iss", "test-app", List.of("second-backend"), "user-1", null, null, null, null, null, null),
                    new TokenSummaryDto("iss", "second-backend", List.of("account"), "user-1", null, null, null, null, null, null)),
            null);

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(new TokenExchangeController(exchangeService))
                .setControllerAdvice(new com.example.second.exception.GlobalExceptionHandler())
                .build();
    }

    @Test
    @DisplayName("POST /api/auth/token-exchange c subject_token в теле")
    void exchangeFromBody() throws Exception {
        when(exchangeService.exchange("alem-token", "openid", "refresh_token")).thenReturn(response);

        mockMvc.perform(post("/api/auth/token-exchange")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"subject_token": "alem-token", "scope": "openid", "requested_token_type": "refresh_token"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").value("new-access"))
                .andExpect(jsonPath("$.exchange.subject.azp").value("test-app"))
                .andExpect(jsonPath("$.exchange.issued.azp").value("second-backend"))
                .andExpect(jsonPath("$.refresh_token").doesNotExist());
    }

    @Test
    @DisplayName("POST /api/auth/token-exchange c токеном в Authorization и без тела")
    void exchangeFromHeader() throws Exception {
        when(exchangeService.exchange("alem-token", null, null)).thenReturn(response);

        mockMvc.perform(post("/api/auth/token-exchange")
                        .header("Authorization", "Bearer alem-token"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").value("new-access"));
    }

    @Test
    @DisplayName("POST /api/auth/token-exchange без токена → 400")
    void exchangeWithoutToken() throws Exception {
        mockMvc.perform(post("/api/auth/token-exchange")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false));
        verifyNoInteractions(exchangeService);
    }

    @Test
    @DisplayName("Ошибка сервиса пробрасывается с её статусом")
    void exchangeServiceError() throws Exception {
        when(exchangeService.exchange(any(), isNull(), isNull()))
                .thenThrow(new AuthException("subject_token не адресован клиенту second-backend", HttpStatus.FORBIDDEN));

        mockMvc.perform(post("/api/auth/token-exchange")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"subject_token\": \"x\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.message").value("subject_token не адресован клиенту second-backend"));
    }

    @Test
    @DisplayName("POST /api/auth/token-exchange/refresh")
    void refresh() throws Exception {
        when(exchangeService.refresh("rt")).thenReturn(response);

        mockMvc.perform(post("/api/auth/token-exchange/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refresh_token\": \"rt\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").value("new-access"));
    }

    @Test
    @DisplayName("POST /api/auth/token-exchange/refresh с пустым токеном → 400")
    void refreshEmpty() throws Exception {
        mockMvc.perform(post("/api/auth/token-exchange/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refresh_token\": \"\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false));
    }

    @Test
    @DisplayName("POST /api/auth/token-exchange/introspect")
    void introspect() throws Exception {
        when(exchangeService.introspect("tok")).thenReturn(new IntrospectionResponse(
                true, "second-backend", "second-backend", null, "user-1", "aitu3", "Bearer", null, null, null, null));

        mockMvc.perform(post("/api/auth/token-exchange/introspect")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\": \"tok\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(true))
                .andExpect(jsonPath("$.client_id").value("second-backend"));
    }
}
