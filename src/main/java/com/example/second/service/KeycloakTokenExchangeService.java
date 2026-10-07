package com.example.second.service;

import com.example.second.dto.TokenExchangeResponse;
import com.example.second.dto.UserInfoDto;
import com.example.second.exception.AuthException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
public class KeycloakTokenExchangeService {

    private static final Logger log = LoggerFactory.getLogger(KeycloakTokenExchangeService.class);

    private static final String GRANT_TYPE_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
    private static final String TOKEN_TYPE_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token";
    private static final String TOKEN_TYPE_REFRESH_TOKEN = "urn:ietf:params:oauth:token-type:refresh_token";

    @Value("${keycloak.server-url:http://localhost:8180}")
    private String serverUrl;

    @Value("${keycloak.realm:GovApps}")
    private String realm;

    @Value("${keycloak.client-id:second-backend}")
    private String clientId;

    @Value("${keycloak.client-secret:}")
    private String clientSecret;

    private final RestClient restClient;
    private final ObjectMapper objectMapper;

    public KeycloakTokenExchangeService() {
        this.restClient = RestClient.builder().build();
        this.objectMapper = new ObjectMapper()
                .configure(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    public KeycloakTokenExchangeService(RestClient restClient, String serverUrl, String realm, String clientId, String clientSecret) {
        this.restClient = restClient;
        this.objectMapper = new ObjectMapper()
                .configure(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        this.serverUrl = serverUrl;
        this.realm = realm;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    /**
     * Обмен access_token от Alem на новые токены second-backend через RFC 8693 Token Exchange в Keycloak.
     */
    public TokenExchangeResponse exchangeAccessToken(String subjectAccessToken) {
        if (subjectAccessToken == null || subjectAccessToken.isBlank()) {
            throw new AuthException("access_token не может быть пустым", HttpStatus.BAD_REQUEST);
        }

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", GRANT_TYPE_TOKEN_EXCHANGE);
        form.add("client_id", clientId);
        if (clientSecret != null && !clientSecret.isBlank()) {
            form.add("client_secret", clientSecret.trim());
        }
        form.add("subject_token", subjectAccessToken.trim());
        form.add("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN);
        form.add("audience", clientId);
        form.add("requested_token_type", TOKEN_TYPE_REFRESH_TOKEN);

        String tokenUrl = String.format("%s/realms/%s/protocol/openid-connect/token", serverUrl, realm);

        log.info("Отправка запроса RFC 8693 Token Exchange в Keycloak: {} (client_id={})", tokenUrl, clientId);

        try {
            String respBody = restClient.post()
                    .uri(tokenUrl)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .retrieve()
                    .body(String.class);

            JsonNode root = objectMapper.readTree(respBody);
            String accessToken = root.path("access_token").asText(null);
            String refreshToken = root.path("refresh_token").asText(null);
            String tokenType = root.path("token_type").asText("Bearer");
            long expiresIn = root.path("expires_in").asLong(300);
            long refreshExpiresIn = root.path("refresh_expires_in").asLong(1800);

            if (accessToken == null || accessToken.isBlank()) {
                throw new AuthException("Keycloak не вернул access_token в ответе Token Exchange", HttpStatus.INTERNAL_SERVER_ERROR);
            }

            UserInfoDto userInfo = extractUserInfoFromToken(accessToken);

            log.info("Token Exchange в Keycloak успешно выполнен для пользователя '{}' (sub={})",
                    userInfo.username(), userInfo.sub());

            return new TokenExchangeResponse(
                    accessToken,
                    refreshToken,
                    tokenType,
                    expiresIn,
                    refreshExpiresIn,
                    userInfo
            );

        } catch (HttpClientErrorException ex) {
            String errorBody = ex.getResponseBodyAsString();
            String message = parseKeycloakErrorMessage(errorBody);
            log.warn("Keycloak отклонил Token Exchange ({}: {}): {}", ex.getStatusCode(), message, errorBody);
            throw new AuthException("Keycloak отклонил Token Exchange: " + message, HttpStatus.BAD_REQUEST);

        } catch (AuthException ae) {
            throw ae;
        } catch (Exception ex) {
            log.error("Ошибка при выполнении Token Exchange в Keycloak: {}", ex.getMessage(), ex);
            throw new AuthException("Не удалось связаться с Keycloak (" + tokenUrl + "): " + ex.getMessage(),
                    HttpStatus.SERVICE_UNAVAILABLE);
        }
    }

    private UserInfoDto extractUserInfoFromToken(String jwtTokenString) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(jwtTokenString);
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

            String sub = claims.getSubject();
            String username = claims.getStringClaim("preferred_username");
            if (username == null || username.isBlank()) {
                username = claims.getStringClaim("username");
            }
            if (username == null || username.isBlank()) {
                username = sub;
            }

            String email = claims.getStringClaim("email");
            String name = claims.getStringClaim("name");

            List<String> roles = extractRoles(claims);

            return new UserInfoDto(sub, username, email, name, roles);
        } catch (Exception e) {
            log.warn("Не удалось распарсить клеймы нового токена: {}", e.getMessage());
            return new UserInfoDto("unknown", "unknown", null, null, List.of());
        }
    }

    private List<String> extractRoles(JWTClaimsSet claims) {
        List<String> roles = new ArrayList<>();
        try {
            Object realmAccessObj = claims.getClaim("realm_access");
            if (realmAccessObj instanceof Map<?, ?> realmAccessMap) {
                Object rolesObj = realmAccessMap.get("roles");
                if (rolesObj instanceof List<?> rolesList) {
                    for (Object r : rolesList) {
                        if (r != null) roles.add(r.toString());
                    }
                }
            }

            // Дополнительно роли ресурса second-backend
            Object resourceAccessObj = claims.getClaim("resource_access");
            if (resourceAccessObj instanceof Map<?, ?> resourceMap) {
                Object clientObj = resourceMap.get(clientId);
                if (clientObj instanceof Map<?, ?> clientMap) {
                    Object clientRoles = clientMap.get("roles");
                    if (clientRoles instanceof List<?> clientRolesList) {
                        for (Object r : clientRolesList) {
                            if (r != null && !roles.contains(r.toString())) {
                                roles.add(r.toString());
                            }
                        }
                    }
                }
            }
        } catch (Exception ignored) {}
        return roles;
    }

    private String parseKeycloakErrorMessage(String errorBody) {
        if (errorBody == null || errorBody.isBlank()) {
            return "Неизвестная ошибка Keycloak";
        }
        try {
            JsonNode node = objectMapper.readTree(errorBody);
            if (node.has("error_description")) {
                return node.get("error_description").asText();
            }
            if (node.has("error")) {
                return node.get("error").asText();
            }
        } catch (Exception ignored) {}
        return errorBody;
    }
}
