package com.example.second.controller;

import com.example.second.dto.ExchangeTokenRequest;
import com.example.second.dto.RefreshTokenRequest;
import com.example.second.dto.TokenExchangeResponse;
import com.example.second.dto.UserInfoDto;
import com.example.second.service.IdTokenValidator;
import com.example.second.service.SecondTokenService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final IdTokenValidator idTokenValidator;
    private final SecondTokenService secondTokenService;

    public AuthController(IdTokenValidator idTokenValidator, SecondTokenService secondTokenService) {
        this.idTokenValidator = idTokenValidator;
        this.secondTokenService = secondTokenService;
    }

    /**
     * Обмен ID-токена (полученного из Alem / Keycloak) на собственные Access и Refresh токены Second Backend.
     */
    @PostMapping("/exchange")
    public ResponseEntity<TokenExchangeResponse> exchangeToken(@Valid @RequestBody ExchangeTokenRequest request) {
        log.info("Получен запрос на обмен ID-токена на токены Second Backend");
        UserInfoDto user = idTokenValidator.validateAndExtractUser(request.idToken());
        TokenExchangeResponse response = secondTokenService.issueTokens(user);
        return ResponseEntity.ok(response);
    }

    /**
     * Обновление пары токенов по Refresh токену Second Backend.
     */
    @PostMapping("/refresh")
    public ResponseEntity<TokenExchangeResponse> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        log.info("Получен запрос на обновление токенов Second Backend");
        TokenExchangeResponse response = secondTokenService.refresh(request.refreshToken());
        return ResponseEntity.ok(response);
    }
}
