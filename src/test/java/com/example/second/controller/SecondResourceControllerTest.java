package com.example.second.controller;

import com.example.second.dto.UserInfoDto;
import com.example.second.service.SecondTokenService;
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

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class SecondResourceControllerTest {

    private MockMvc mockMvc;

    @Mock
    private SecondTokenService secondTokenService;

    @BeforeEach
    void setUp() {
        SecondResourceController controller = new SecondResourceController(secondTokenService);
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new com.example.second.exception.GlobalExceptionHandler())
                .build();
    }

    @Test
    @DisplayName("GET /api/second/me с валидным Bearer токеном возвращает 200 OK и данные пользователя")
    void testGetMeSuccess() throws Exception {
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
                .andExpect(jsonPath("$.data.user.username").value("aitu3"))
                .andExpect(jsonPath("$.data.service").value("second-backend"));
    }

    @Test
    @DisplayName("GET /api/second/me без заголовка Authorization возвращает 400/401")
    void testGetMeWithoutAuthHeader() throws Exception {
        mockMvc.perform(get("/api/second/me"))
                .andExpect(status().isUnauthorized());
    }
}
