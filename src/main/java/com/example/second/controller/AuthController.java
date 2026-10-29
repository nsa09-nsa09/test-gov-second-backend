package com.example.second.controller;

import com.example.second.dto.ApiResponse;
import com.example.second.dto.ExchangeAccessTokenRequest;
import com.example.second.dto.ExchangeTokenRequest;
import com.example.second.dto.RefreshTokenRequest;
import com.example.second.dto.TokenExchangeResponse;
import com.example.second.dto.UserInfoDto;
import com.example.second.service.IdTokenValidator;
import com.example.second.service.KeycloakTokenExchangeService;
import com.example.second.service.SecondTokenService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@Tag(name = "4. Legacy", description = "Старые сценарии: собственные HS256-токены second-backend и прежний endpoint обмена")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final IdTokenValidator idTokenValidator;
    private final SecondTokenService secondTokenService;
    private final KeycloakTokenExchangeService keycloakTokenExchangeService;

    public AuthController(IdTokenValidator idTokenValidator,
                          SecondTokenService secondTokenService,
                          KeycloakTokenExchangeService keycloakTokenExchangeService) {
        this.idTokenValidator = idTokenValidator;
        this.secondTokenService = secondTokenService;
        this.keycloakTokenExchangeService = keycloakTokenExchangeService;
    }

    /**
     * Обмен ID-токена (полученного из Alem / Keycloak) на собственные Access и Refresh токены Second Backend.
     */
    @PostMapping("/exchange")
    @Operation(
            summary = "Обменять id_token на HS256-токены second-backend",
            description = "Проверяет `id_token` по JWKS alem (`/api/auth/jwks`) и выпускает собственные HS256 access (15 мин) и refresh (7 дней) токены. Keycloak в обмене не участвует."
    )
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Токены выпущены",
                    content = @Content(schema = @Schema(implementation = TokenExchangeResponse.class))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "400", description = "Пустой или некорректный id_token",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "Подпись или срок id_token не прошли проверку",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "503", description = "JWKS alem недоступен",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class)))
    })
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
    @Operation(
            summary = "Обновить HS256-токены second-backend",
            description = "Только для refresh token из `POST /api/auth/exchange`. Для токенов Keycloak используйте `POST /api/auth/token-exchange/refresh`."
    )
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Новая пара токенов",
                    content = @Content(schema = @Schema(implementation = TokenExchangeResponse.class))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "Refresh token невалиден или истёк",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class)))
    })
    public ResponseEntity<TokenExchangeResponse> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        log.info("Получен запрос на обновление токенов Second Backend");
        TokenExchangeResponse response = secondTokenService.refresh(request.refreshToken());
        return ResponseEntity.ok(response);
    }

    /**
     * Обмен Access Token от Alem на токены Second Backend через Keycloak RFC 8693 Token Exchange.
     *
     * @deprecated используйте POST /api/auth/token-exchange
     */
    @Deprecated
    @PostMapping("/exchange-access-token")
    @Operation(
            summary = "[Deprecated] Обмен access token через Keycloak",
            description = "Оставлен для обратной совместимости и вызывает ту же логику, что и `POST /api/auth/token-exchange`, но в старом формате ответа (без блока `exchange`). Используйте `POST /api/auth/token-exchange`.",
            deprecated = true
    )
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Обмен выполнен",
                    content = @Content(schema = @Schema(implementation = TokenExchangeResponse.class))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "400", description = "Пустой access_token или Keycloak отклонил обмен",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "access_token не прошёл проверку",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "403", description = "access_token не адресован second-backend",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class)))
    })
    public ResponseEntity<TokenExchangeResponse> exchangeAccessToken(@Valid @RequestBody ExchangeAccessTokenRequest request) {
        log.info("Получен запрос на обмен Access Token через Keycloak RFC 8693 Token Exchange (legacy endpoint)");
        TokenExchangeResponse response = keycloakTokenExchangeService.exchangeAccessToken(request.accessToken());
        return ResponseEntity.ok(response);
    }
}
