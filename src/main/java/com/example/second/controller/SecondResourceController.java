package com.example.second.controller;

import com.example.second.dto.ApiResponse;
import com.example.second.dto.UserInfoDto;
import com.example.second.exception.AuthException;
import com.example.second.service.SecondTokenService;
import com.nimbusds.jwt.JWTClaimsSet;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Map;

@RestController
@RequestMapping("/api/second")
public class SecondResourceController {

    private final SecondTokenService secondTokenService;

    public SecondResourceController(SecondTokenService secondTokenService) {
        this.secondTokenService = secondTokenService;
    }

    /**
     * Защищенный эндпоинт Second Backend, требующий валидный Access Token Second Backend.
     */
    @GetMapping("/me")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getMe(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new AuthException("Отсутствует или некорректен заголовок Authorization: ожидается 'Bearer <token>'",
                    HttpStatus.UNAUTHORIZED);
        }

        String token = authHeader.substring(7).trim();
        JWTClaimsSet claims = secondTokenService.validateToken(token, "access");
        UserInfoDto user = secondTokenService.extractUser(claims);

        Map<String, Object> data = Map.of(
                "user", user,
                "service", "second-backend",
                "issuer", claims.getIssuer(),
                "audience", claims.getAudience(),
                "expires_at", claims.getExpirationTime() != null ? claims.getExpirationTime().toString() : "—",
                "authorized_at", Instant.now().toString()
        );

        return ResponseEntity.ok(ApiResponse.ok("Успешная авторизация в Second Backend", data));
    }
}
