package com.example.second.service;

import com.example.second.dto.ExchangeDetailsDto;
import com.example.second.dto.IntrospectionResponse;
import com.example.second.dto.KeycloakTokenResponse;
import com.example.second.dto.TokenExchangeResponse;
import com.example.second.dto.TokenSummaryDto;
import com.example.second.dto.UserInfoDto;
import com.example.second.exception.AuthException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestClient;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Взаимодействие second-backend с Keycloak от имени confidential-клиента second-backend:
 * RFC 8693 Standard Token Exchange, refresh_token grant и introspection (RFC 7662).
 */
@Service
public class KeycloakTokenExchangeService {

    private static final Logger log = LoggerFactory.getLogger(KeycloakTokenExchangeService.class);

    static final String GRANT_TYPE_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
    static final String TOKEN_TYPE_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token";
    static final String TOKEN_TYPE_REFRESH_TOKEN = "urn:ietf:params:oauth:token-type:refresh_token";

    private final RestClient restClient;
    private final ObjectMapper objectMapper = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    private final KeycloakTokenValidator tokenValidator;
    private final String realmUrl;
    private final String clientId;
    private final String clientSecret;

    @Autowired
    public KeycloakTokenExchangeService(KeycloakTokenValidator tokenValidator,
                                        @Value("${keycloak.server-url:http://localhost:8180}") String serverUrl,
                                        @Value("${keycloak.realm:GovApps}") String realm,
                                        @Value("${keycloak.client-id:second-backend}") String clientId,
                                        @Value("${keycloak.client-secret:}") String clientSecret) {
        this(RestClient.builder().build(), tokenValidator, serverUrl, realm, clientId, clientSecret);
    }

    public KeycloakTokenExchangeService(RestClient restClient, KeycloakTokenValidator tokenValidator,
                                        String serverUrl, String realm, String clientId, String clientSecret) {
        this.restClient = restClient;
        this.tokenValidator = tokenValidator;
        this.realmUrl = String.format("%s/realms/%s", serverUrl, realm);
        this.clientId = clientId;
        this.clientSecret = clientSecret != null ? clientSecret.trim() : "";
    }

    public String getClientId() {
        return clientId;
    }

    /**
     * RFC 8693: обмен access-токена alem (subject_token) на новый токен клиента second-backend.
     * Перед запросом в Keycloak subject_token проверяется локально (подпись, iss, exp, aud).
     */
    public KeycloakTokenResponse exchange(String subjectToken, String scope, String requestedTokenType) {
        if (subjectToken == null || subjectToken.isBlank()) {
            throw new AuthException("subject_token не может быть пустым", HttpStatus.BAD_REQUEST);
        }
        String subject = subjectToken.trim();

        JWTClaimsSet subjectClaims = tokenValidator.validate(subject, null);
        List<String> audience = subjectClaims.getAudience();
        if (audience == null || !audience.contains(clientId)) {
            throw new AuthException("subject_token не адресован клиенту " + clientId + " (aud=" + audience + "). "
                    + "Добавьте Audience mapper '" + clientId + "' в клиент, выдавший токен (azp="
                    + subjectClaims.getClaim("azp") + ")", HttpStatus.FORBIDDEN);
        }

        String requestedType = resolveRequestedTokenType(requestedTokenType);

        MultiValueMap<String, String> form = clientForm();
        form.add("grant_type", GRANT_TYPE_TOKEN_EXCHANGE);
        form.add("subject_token", subject);
        form.add("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN);
        form.add("requested_token_type", requestedType);
        if (scope != null && !scope.isBlank()) {
            form.add("scope", scope.trim());
        }

        log.info("RFC 8693 Token Exchange: sub={}, azp={} -> client_id={}",
                subjectClaims.getSubject(), subjectClaims.getClaim("azp"), clientId);

        JsonNode body = postForm(tokenUrl(), form, "Token Exchange");
        KeycloakTokenResponse issued = toTokenResponse(body,
                new ExchangeDetailsDto(TokenClaimsMapper.summarize(subjectClaims), null));

        log.info("Token Exchange выполнен: пользователь '{}' получил токен azp={}",
                issued.user().username(), issued.exchange().issued() != null ? issued.exchange().issued().azp() : "?");
        return issued;
    }

    /**
     * Legacy-формат ответа для POST /api/auth/exchange-access-token.
     */
    public TokenExchangeResponse exchangeAccessToken(String subjectToken) {
        KeycloakTokenResponse r = exchange(subjectToken, null, null);
        return new TokenExchangeResponse(r.accessToken(), r.refreshToken(), r.tokenType(),
                r.expiresIn(), r.refreshExpiresIn(), r.user());
    }

    /**
     * Обновление токенов second-backend по refresh_token Keycloak.
     */
    public KeycloakTokenResponse refresh(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new AuthException("refresh_token не может быть пустым", HttpStatus.BAD_REQUEST);
        }

        MultiValueMap<String, String> form = clientForm();
        form.add("grant_type", "refresh_token");
        form.add("refresh_token", refreshToken.trim());

        return toTokenResponse(postForm(tokenUrl(), form, "Refresh"), null);
    }

    /**
     * Introspection любого токена realm от имени second-backend.
     */
    public IntrospectionResponse introspect(String token) {
        if (token == null || token.isBlank()) {
            throw new AuthException("token не может быть пустым", HttpStatus.BAD_REQUEST);
        }

        MultiValueMap<String, String> form = clientForm();
        form.add("token", token.trim());

        JsonNode node = postForm(realmUrl + "/protocol/openid-connect/token/introspect", form, "Introspection");

        List<String> aud = new ArrayList<>();
        JsonNode audNode = node.path("aud");
        if (audNode.isArray()) {
            audNode.forEach(a -> aud.add(a.asText()));
        } else if (audNode.isTextual()) {
            aud.add(audNode.asText());
        }

        return new IntrospectionResponse(
                node.path("active").asBoolean(false),
                text(node, "client_id"),
                text(node, "azp"),
                aud.isEmpty() ? null : aud,
                text(node, "sub"),
                text(node, "username"),
                text(node, "token_type"),
                text(node, "scope"),
                text(node, "iss"),
                epochToIso(node.path("iat")),
                epochToIso(node.path("exp"))
        );
    }

    private KeycloakTokenResponse toTokenResponse(JsonNode root, ExchangeDetailsDto exchange) {
        String accessToken = text(root, "access_token");
        if (accessToken == null || accessToken.isBlank()) {
            throw new AuthException("Keycloak не вернул access_token", HttpStatus.BAD_GATEWAY);
        }
        String refreshToken = text(root, "refresh_token");

        UserInfoDto user;
        TokenSummaryDto issuedSummary;
        try {
            JWTClaimsSet claims = SignedJWT.parse(accessToken).getJWTClaimsSet();
            user = TokenClaimsMapper.extractUser(claims, clientId);
            issuedSummary = TokenClaimsMapper.summarize(claims);
        } catch (Exception e) {
            throw new AuthException("Keycloak вернул некорректный access_token: " + e.getMessage(), HttpStatus.BAD_GATEWAY);
        }

        String hint = null;
        if (refreshToken == null && exchange != null) {
            hint = "Keycloak не выдал refresh_token. Чтобы получить его, передайте requested_token_type=refresh_token "
                    + "и включите Clients → " + clientId + " → Advanced → 'Allow refresh token in Standard Token Exchange' = Same session.";
        }

        return new KeycloakTokenResponse(
                accessToken,
                refreshToken,
                root.path("token_type").asText("Bearer"),
                root.path("expires_in").asLong(0),
                refreshToken != null ? root.path("refresh_expires_in").asLong(0) : 0,
                text(root, "issued_token_type"),
                text(root, "scope"),
                user,
                exchange != null ? new ExchangeDetailsDto(exchange.subject(), issuedSummary) : null,
                hint
        );
    }

    private JsonNode postForm(String url, MultiValueMap<String, String> form, String operation) {
        try {
            String body = restClient.post()
                    .uri(url)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .retrieve()
                    .body(String.class);
            return objectMapper.readTree(body != null ? body : "{}");
        } catch (HttpClientErrorException ex) {
            throw keycloakError(operation, ex.getStatusCode().value(), ex.getResponseBodyAsString());
        } catch (HttpServerErrorException ex) {
            log.error("Keycloak {} вернул {}: {}", operation, ex.getStatusCode(), ex.getResponseBodyAsString());
            throw new AuthException("Keycloak вернул ошибку " + ex.getStatusCode().value() + " на " + operation,
                    HttpStatus.BAD_GATEWAY);
        } catch (AuthException ex) {
            throw ex;
        } catch (Exception ex) {
            log.error("Keycloak недоступен ({}): {}", url, ex.getMessage());
            throw new AuthException("Не удалось связаться с Keycloak (" + url + "): " + ex.getMessage(),
                    HttpStatus.SERVICE_UNAVAILABLE);
        }
    }

    /**
     * Перевод OAuth-ошибки Keycloak в HTTP-статус и понятное сообщение.
     */
    AuthException keycloakError(String operation, int httpStatus, String errorBody) {
        String error = null;
        String description = null;
        try {
            JsonNode node = objectMapper.readTree(errorBody);
            error = text(node, "error");
            description = text(node, "error_description");
        } catch (Exception ignored) {}

        String message = description != null ? description : (error != null ? error : "HTTP " + httpStatus);
        log.warn("Keycloak отклонил {} ({} {}): {}", operation, httpStatus, error, message);

        HttpStatus status = switch (error != null ? error : "") {
            case "invalid_client" -> HttpStatus.UNAUTHORIZED;
            case "access_denied", "unauthorized_client" -> HttpStatus.FORBIDDEN;
            default -> HttpStatus.BAD_REQUEST;
        };

        String hint = "";
        if (message.contains("Standard token exchange is not enabled")) {
            hint = " Включите Clients → " + clientId + " → Settings → Capability config → Standard Token Exchange.";
        } else if ("invalid_client".equals(error)) {
            hint = " Проверьте keycloak.client-id / keycloak.client-secret (Clients → " + clientId + " → Credentials).";
        } else if (message.toLowerCase().contains("audience")) {
            hint = " Проверьте Audience mapper '" + clientId + "' у клиента, выдавшего subject_token.";
        } else if (message.toLowerCase().contains("refresh token")) {
            hint = " Включите Clients → " + clientId + " → Advanced → 'Allow refresh token in Standard Token Exchange'.";
        }

        return new AuthException("Keycloak отклонил " + operation + ": " + message + hint, status);
    }

    private String resolveRequestedTokenType(String requested) {
        if (requested == null || requested.isBlank() || "access_token".equals(requested) || TOKEN_TYPE_ACCESS_TOKEN.equals(requested)) {
            return TOKEN_TYPE_ACCESS_TOKEN;
        }
        if ("refresh_token".equals(requested) || TOKEN_TYPE_REFRESH_TOKEN.equals(requested)) {
            return TOKEN_TYPE_REFRESH_TOKEN;
        }
        throw new AuthException("requested_token_type должен быть access_token или refresh_token", HttpStatus.BAD_REQUEST);
    }

    private MultiValueMap<String, String> clientForm() {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("client_id", clientId);
        if (!clientSecret.isBlank()) {
            form.add("client_secret", clientSecret);
        }
        return form;
    }

    private String tokenUrl() {
        return realmUrl + "/protocol/openid-connect/token";
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value != null && !value.isNull() ? value.asText() : null;
    }

    private static String epochToIso(JsonNode node) {
        return node.isNumber() ? Instant.ofEpochSecond(node.asLong()).toString() : null;
    }
}
