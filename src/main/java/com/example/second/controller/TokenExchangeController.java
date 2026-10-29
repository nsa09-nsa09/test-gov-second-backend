package com.example.second.controller;

import com.example.second.config.OpenApiConfig;
import com.example.second.dto.ApiResponse;
import com.example.second.dto.IntrospectRequest;
import com.example.second.dto.IntrospectionResponse;
import com.example.second.dto.KeycloakTokenResponse;
import com.example.second.dto.RefreshTokenRequest;
import com.example.second.dto.TokenExchangeRequest;
import com.example.second.exception.AuthException;
import com.example.second.service.KeycloakTokenExchangeService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth/token-exchange")
@Tag(name = "1. Token Exchange", description = "RFC 8693: обмен access-токена alem на токен second-backend через Keycloak")
public class TokenExchangeController {

    private static final Logger log = LoggerFactory.getLogger(TokenExchangeController.class);

    private final KeycloakTokenExchangeService exchangeService;

    public TokenExchangeController(KeycloakTokenExchangeService exchangeService) {
        this.exchangeService = exchangeService;
    }

    @PostMapping
    @Operation(
            summary = "Обменять access token alem на токен second-backend",
            description = """
                    Принимает access token, выданный alem (`azp=test-app`), и выполняет в Keycloak
                    **RFC 8693 Standard Token Exchange** от имени confidential-клиента `second-backend`.

                    **Порядок работы:**
                    1. `subject_token` берётся из тела запроса, а если его нет — из заголовка `Authorization: Bearer`.
                    2. Локальная проверка subject_token: подпись RS256 по JWKS Keycloak, `iss`, `exp`,
                       `aud` содержит `second-backend` (иначе Keycloak всё равно отклонит обмен).
                    3. `POST {keycloak}/realms/GovApps/protocol/openid-connect/token` c
                       `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`.
                    4. Возвращается новый токен (`azp=second-backend`) и блок `exchange` со сравнением claims до/после.

                    Полученный `access_token` используйте для `GET /api/second/me`.
                    """,
            security = @SecurityRequirement(name = OpenApiConfig.BEARER_SCHEME)
    )
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Обмен выполнен",
                    content = @Content(schema = @Schema(implementation = KeycloakTokenResponse.class), examples = @ExampleObject("""
                            {
                              "access_token": "eyJhbGciOiJSUzI1NiIs...",
                              "token_type": "Bearer",
                              "expires_in": 300,
                              "refresh_expires_in": 0,
                              "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                              "scope": "profile email",
                              "user": {"sub": "b2f67ac1-...", "username": "aitu3", "email": "aitu3@example.com", "name": "Aitu User", "roles": ["user"]},
                              "exchange": {
                                "subject": {"iss": "http://localhost:8180/realms/GovApps", "azp": "test-app", "aud": ["second-backend", "account"], "sub": "b2f67ac1-...", "exp": "2026-10-29T18:05:00Z"},
                                "issued":  {"iss": "http://localhost:8180/realms/GovApps", "azp": "second-backend", "aud": ["account"], "sub": "b2f67ac1-...", "exp": "2026-10-29T18:06:00Z"}
                              },
                              "hint": "Keycloak не выдал refresh_token. ..."
                            }"""))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "400", description = "Пустой/некорректный запрос или Keycloak отклонил обмен (invalid_request, invalid_token)",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class), examples = @ExampleObject("""
                            {"success": false, "message": "subject_token не может быть пустым"}"""))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "subject_token не прошёл проверку (подпись, iss, exp) или неверные креды second-backend (invalid_client)",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class), examples = @ExampleObject("""
                            {"success": false, "message": "Токен отклонён (expiration): Срок действия истёк 2026-10-29T18:05:00Z"}"""))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "403", description = "subject_token не адресован second-backend (нет aud) или Keycloak запретил обмен (access_denied)",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class), examples = @ExampleObject("""
                            {"success": false, "message": "subject_token не адресован клиенту second-backend (aud=[account]). Добавьте Audience mapper 'second-backend' в клиент, выдавший токен (azp=test-app)"}"""))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "503", description = "Keycloak недоступен",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class), examples = @ExampleObject("""
                            {"success": false, "message": "Не удалось связаться с Keycloak (http://localhost:8180/...): Connection refused"}""")))
    })
    public ResponseEntity<KeycloakTokenResponse> exchange(
            @RequestBody(required = false) TokenExchangeRequest request,
            @Parameter(hidden = true) @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authHeader) {

        String subjectToken = request != null ? request.subjectToken() : null;
        if ((subjectToken == null || subjectToken.isBlank()) && authHeader != null && authHeader.startsWith("Bearer ")) {
            subjectToken = authHeader.substring(7);
        }
        if (subjectToken == null || subjectToken.isBlank()) {
            throw new AuthException("subject_token не может быть пустым: передайте его в теле или в заголовке Authorization: Bearer",
                    HttpStatus.BAD_REQUEST);
        }

        log.info("POST /api/auth/token-exchange");
        return ResponseEntity.ok(exchangeService.exchange(
                subjectToken,
                request != null ? request.scope() : null,
                request != null ? request.requestedTokenType() : null));
    }

    @PostMapping("/refresh")
    @Operation(
            summary = "Обновить токен second-backend по refresh_token",
            description = """
                    `grant_type=refresh_token` в Keycloak от имени `second-backend`.
                    refresh_token выдаётся при обмене, только если запрошен `requested_token_type=refresh_token`
                    и у клиента включено Advanced → *Allow refresh token in Standard Token Exchange*.
                    """
    )
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Новая пара токенов",
                    content = @Content(schema = @Schema(implementation = KeycloakTokenResponse.class))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "400", description = "Refresh token невалиден, истёк или выдан другому клиенту (invalid_grant)",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class), examples = @ExampleObject("""
                            {"success": false, "message": "Keycloak отклонил Refresh: Invalid refresh token"}"""))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "503", description = "Keycloak недоступен",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class)))
    })
    public ResponseEntity<KeycloakTokenResponse> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(exchangeService.refresh(request.refreshToken()));
    }

    @PostMapping("/introspect")
    @Operation(
            summary = "Проверить токен через Keycloak introspection",
            description = """
                    RFC 7662 introspection от имени `second-backend`. Позволяет убедиться, что токен активен
                    в Keycloak и посмотреть, кому он выдан (`client_id`/`azp`).
                    Для токена alem будет `azp=test-app`, для обменянного — `azp=second-backend`.
                    Неактивный/отозванный/истёкший токен возвращает `{"active": false}` со статусом 200.
                    """
    )
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Результат introspection",
                    content = @Content(schema = @Schema(implementation = IntrospectionResponse.class), examples = {
                            @ExampleObject(name = "Активный токен second-backend", value = """
                                    {"active": true, "client_id": "second-backend", "azp": "second-backend", "sub": "b2f67ac1-...", "username": "aitu3", "token_type": "Bearer", "iss": "http://localhost:8180/realms/GovApps", "exp": "2026-10-29T18:06:00Z"}"""),
                            @ExampleObject(name = "Неактивный токен", value = """
                                    {"active": false}""")
                    })),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "400", description = "Пустой token",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "Неверные креды second-backend (invalid_client)",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "503", description = "Keycloak недоступен",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class)))
    })
    public ResponseEntity<IntrospectionResponse> introspect(@Valid @RequestBody IntrospectRequest request) {
        return ResponseEntity.ok(exchangeService.introspect(request.token()));
    }
}
