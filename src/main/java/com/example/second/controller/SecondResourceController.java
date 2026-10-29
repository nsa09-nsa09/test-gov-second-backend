package com.example.second.controller;

import com.example.second.config.OpenApiConfig;
import com.example.second.dto.ApiResponse;
import com.example.second.dto.TokenCheckDto;
import com.example.second.dto.TokenInfoResponse;
import com.example.second.dto.UserInfoDto;
import com.example.second.exception.AuthException;
import com.example.second.service.KeycloakTokenValidator;
import com.example.second.service.SecondTokenService;
import com.example.second.service.TokenClaimsMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.text.ParseException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/second")
public class SecondResourceController {

    private static final String KIND_KEYCLOAK = "keycloak";
    private static final String KIND_SECOND_LEGACY = "second-legacy";

    private final SecondTokenService secondTokenService;
    private final KeycloakTokenValidator keycloakTokenValidator;
    private final String clientId;

    public SecondResourceController(SecondTokenService secondTokenService,
                                    KeycloakTokenValidator keycloakTokenValidator,
                                    @Value("${keycloak.client-id:second-backend}") String clientId) {
        this.secondTokenService = secondTokenService;
        this.keycloakTokenValidator = keycloakTokenValidator;
        this.clientId = clientId;
    }

    /**
     * Защищённый эндпоинт. Принимает Keycloak RS256 токены, выданные именно second-backend (azp),
     * и legacy HS256 токены, выпущенные самим second-backend через /api/auth/exchange.
     */
    @GetMapping("/me")
    @Tag(name = "2. Protected", description = "Ресурсы second-backend, доступные только с токеном second-backend")
    @Operation(
            summary = "Защищённый ресурс: кто я",
            description = """
                    Требует `Authorization: Bearer <token>`. Принимаются:
                    - **Keycloak RS256** токен с `azp=second-backend` — результат `POST /api/auth/token-exchange`.
                      Проверяются подпись (JWKS Keycloak), `iss`, `exp` и `azp`.
                    - **Legacy HS256** токен second-backend из `POST /api/auth/exchange`.

                    Исходный токен alem (`azp=test-app`) отклоняется с 401 — так можно убедиться,
                    что обмен действительно нужен и работает. Причину отказа подробно показывает `GET /api/second/token-info`.
                    """,
            security = @SecurityRequirement(name = OpenApiConfig.BEARER_SCHEME)
    )
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Токен принят",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class), examples = @ExampleObject("""
                            {
                              "success": true,
                              "message": "Успешная авторизация в Second Backend",
                              "data": {
                                "service": "second-backend",
                                "token_kind": "keycloak",
                                "issuer": "http://localhost:8180/realms/GovApps",
                                "azp": "second-backend",
                                "audience": ["account"],
                                "expires_at": "2026-10-29T18:06:00Z",
                                "authorized_at": "2026-10-29T18:01:12Z",
                                "user": {"sub": "b2f67ac1-...", "username": "aitu3", "email": "aitu3@example.com", "name": "Aitu User", "roles": ["user"]}
                              }
                            }"""))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "Нет токена, токен невалиден или выдан не second-backend",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class), examples = {
                            @ExampleObject(name = "Токен alem (без обмена)", value = """
                                    {"success": false, "message": "Токен отклонён (authorized_party): azp='test-app', ожидается 'second-backend'. Получите токен через POST /api/auth/token-exchange"}"""),
                            @ExampleObject(name = "Нет заголовка", value = """
                                    {"success": false, "message": "Отсутствует или некорректен заголовок Authorization: ожидается 'Bearer <token>'"}""")
                    })),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "503", description = "JWKS Keycloak недоступен",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class)))
    })
    public ResponseEntity<ApiResponse<Map<String, Object>>> getMe(
            @Parameter(hidden = true) @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authHeader) {

        String token = extractBearer(authHeader);
        boolean keycloakToken = isRsaToken(token);

        JWTClaimsSet claims;
        UserInfoDto user;
        if (keycloakToken) {
            claims = keycloakTokenValidator.validate(token, clientId);
            user = TokenClaimsMapper.extractUser(claims, clientId);
        } else {
            claims = secondTokenService.validateToken(token, "access");
            user = secondTokenService.extractUser(claims);
        }

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("service", "second-backend");
        data.put("token_kind", keycloakToken ? KIND_KEYCLOAK : KIND_SECOND_LEGACY);
        data.put("issuer", claims.getIssuer() != null ? claims.getIssuer() : "—");
        data.put("azp", claims.getClaim("azp") != null ? claims.getClaim("azp") : "—");
        data.put("audience", claims.getAudience() != null ? claims.getAudience() : List.of());
        data.put("expires_at", claims.getExpirationTime() != null ? claims.getExpirationTime().toInstant().toString() : "—");
        data.put("authorized_at", Instant.now().toString());
        data.put("user", user);

        return ResponseEntity.ok(ApiResponse.ok("Успешная авторизация в Second Backend", data));
    }

    @GetMapping("/token-info")
    @Tag(name = "3. Debug", description = "Диагностика токенов")
    @Operation(
            summary = "Отладка: примет ли /me этот токен и почему",
            description = """
                    Декодирует Bearer-токен и выполняет те же проверки, что и `GET /api/second/me`,
                    но не прерывается на первой ошибке и всегда отвечает 200 с отчётом.
                    Удобно сравнить токен alem (`accepted_by_me=false`, провал `authorized_party`)
                    и токен после обмена (`accepted_by_me=true`).
                    """,
            security = @SecurityRequirement(name = OpenApiConfig.BEARER_SCHEME)
    )
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Отчёт о проверках",
                    content = @Content(schema = @Schema(implementation = TokenInfoResponse.class), examples = @ExampleObject("""
                            {
                              "alg": "RS256",
                              "kid": "Xx9kQ...",
                              "kind": "keycloak",
                              "claims": {"iss": "http://localhost:8180/realms/GovApps", "azp": "test-app", "aud": ["second-backend", "account"], "sub": "b2f67ac1-...", "exp": "2026-10-29T18:05:00Z"},
                              "checks": [
                                {"name": "format", "passed": true, "detail": "JWT распарсен"},
                                {"name": "signature", "passed": true, "detail": "RS256, ключ kid='Xx9kQ...' из JWKS Keycloak"},
                                {"name": "issuer", "passed": true, "detail": "iss='http://localhost:8180/realms/GovApps'"},
                                {"name": "expiration", "passed": true, "detail": "Действует до 2026-10-29T18:05:00Z"},
                                {"name": "authorized_party", "passed": false, "detail": "azp='test-app', ожидается 'second-backend'. Получите токен через POST /api/auth/token-exchange"}
                              ],
                              "accepted_by_me": false
                            }"""))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "Нет заголовка Authorization",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class)))
    })
    public ResponseEntity<TokenInfoResponse> tokenInfo(
            @Parameter(hidden = true) @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authHeader) {

        String token = extractBearer(authHeader);

        SignedJWT jwt;
        try {
            jwt = SignedJWT.parse(token);
        } catch (ParseException e) {
            return ResponseEntity.ok(new TokenInfoResponse(null, null, null, null,
                    List.of(TokenCheckDto.fail(KeycloakTokenValidator.CHECK_FORMAT, "Некорректный JWT: " + e.getMessage())), false));
        }

        String alg = jwt.getHeader().getAlgorithm() != null ? jwt.getHeader().getAlgorithm().getName() : null;
        String kid = jwt.getHeader().getKeyID();

        if (isRsaToken(token)) {
            KeycloakTokenValidator.ValidationReport report = keycloakTokenValidator.inspect(token, clientId);
            return ResponseEntity.ok(new TokenInfoResponse(alg, kid, KIND_KEYCLOAK,
                    TokenClaimsMapper.summarize(report.claims()), report.checks(), report.passed()));
        }

        TokenCheckDto legacyCheck;
        try {
            secondTokenService.validateToken(token, "access");
            legacyCheck = TokenCheckDto.ok("second_hs256", "Валидный HS256 access token second-backend");
        } catch (AuthException e) {
            legacyCheck = TokenCheckDto.fail("second_hs256", e.getMessage());
        }
        return ResponseEntity.ok(new TokenInfoResponse(alg, kid, KIND_SECOND_LEGACY,
                TokenClaimsMapper.summarize(token), List.of(legacyCheck), legacyCheck.passed()));
    }

    private static String extractBearer(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ") || authHeader.substring(7).isBlank()) {
            throw new AuthException("Отсутствует или некорректен заголовок Authorization: ожидается 'Bearer <token>'",
                    HttpStatus.UNAUTHORIZED);
        }
        return authHeader.substring(7).trim();
    }

    private static boolean isRsaToken(String token) {
        try {
            return JWSAlgorithm.Family.RSA.contains(SignedJWT.parse(token).getHeader().getAlgorithm());
        } catch (ParseException e) {
            return false;
        }
    }
}
