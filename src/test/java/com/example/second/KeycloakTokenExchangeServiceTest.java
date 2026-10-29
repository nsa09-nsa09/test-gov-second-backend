package com.example.second;

import com.example.second.dto.IntrospectionResponse;
import com.example.second.dto.KeycloakTokenResponse;
import com.example.second.exception.AuthException;
import com.example.second.service.KeycloakJwksService;
import com.example.second.service.KeycloakTokenExchangeService;
import com.example.second.service.KeycloakTokenValidator;
import com.example.second.support.TestTokens;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

class KeycloakTokenExchangeServiceTest {

    private static final String TOKEN_URL = "http://kc/realms/GovApps/protocol/openid-connect/token";
    private static final String INTROSPECT_URL = TOKEN_URL + "/introspect";

    private MockRestServiceServer server;
    private KeycloakTokenExchangeService service;

    @BeforeEach
    void setUp() {
        KeycloakJwksService jwksService = Mockito.mock(KeycloakJwksService.class);
        when(jwksService.getKeyByKeyId(TestTokens.KID)).thenReturn(TestTokens.KEY.toPublicJWK());
        KeycloakTokenValidator validator = new KeycloakTokenValidator(jwksService, TestTokens.ISSUER);

        RestClient.Builder builder = RestClient.builder();
        server = MockRestServiceServer.bindTo(builder).build();
        service = new KeycloakTokenExchangeService(builder.build(), validator,
                "http://kc", "GovApps", "second-backend", "secret");
    }

    @Test
    @DisplayName("Успешный обмен: в Keycloak уходит RFC 8693 запрос, в ответе claims до/после")
    void exchangeSuccess() {
        String subject = TestTokens.alemToken();
        String issued = TestTokens.secondToken();

        server.expect(requestTo(TOKEN_URL))
                .andExpect(method(HttpMethod.POST))
                .andExpect(content().formDataContains(java.util.Map.of(
                        "grant_type", "urn:ietf:params:oauth:grant-type:token-exchange",
                        "client_id", "second-backend",
                        "client_secret", "secret",
                        "subject_token", subject,
                        "subject_token_type", "urn:ietf:params:oauth:token-type:access_token",
                        "requested_token_type", "urn:ietf:params:oauth:token-type:access_token")))
                .andRespond(withSuccess("""
                        {"access_token": "%s", "token_type": "Bearer", "expires_in": 300,
                         "issued_token_type": "urn:ietf:params:oauth:token-type:access_token", "scope": "profile email"}
                        """.formatted(issued), MediaType.APPLICATION_JSON));

        KeycloakTokenResponse r = service.exchange(subject, null, null);

        assertEquals(issued, r.accessToken());
        assertNull(r.refreshToken());
        assertNotNull(r.hint(), "Без refresh_token должна быть подсказка");
        assertEquals(300, r.expiresIn());
        assertEquals("aitu3", r.user().username());
        assertTrue(r.user().roles().containsAll(List.of("user", "reader")));
        assertEquals("test-app", r.exchange().subject().azp());
        assertEquals("second-backend", r.exchange().issued().azp());
        server.verify();
    }

    @Test
    @DisplayName("requested_token_type=refresh_token и scope передаются в Keycloak, refresh_token возвращается")
    void exchangeWithRefreshTokenAndScope() {
        server.expect(requestTo(TOKEN_URL))
                .andExpect(content().formDataContains(java.util.Map.of(
                        "requested_token_type", "urn:ietf:params:oauth:token-type:refresh_token",
                        "scope", "openid")))
                .andRespond(withSuccess("""
                        {"access_token": "%s", "refresh_token": "rt-1", "expires_in": 300, "refresh_expires_in": 1800}
                        """.formatted(TestTokens.secondToken()), MediaType.APPLICATION_JSON));

        KeycloakTokenResponse r = service.exchange(TestTokens.alemToken(), "openid", "refresh_token");

        assertEquals("rt-1", r.refreshToken());
        assertEquals(1800, r.refreshExpiresIn());
        assertNull(r.hint());
        server.verify();
    }

    @Test
    @DisplayName("Пустой subject_token → 400 без запроса в Keycloak")
    void exchangeEmpty() {
        assertEquals(HttpStatus.BAD_REQUEST, assertThrows(AuthException.class, () -> service.exchange(" ", null, null)).getStatus());
        assertEquals(HttpStatus.BAD_REQUEST, assertThrows(AuthException.class, () -> service.exchange(null, null, null)).getStatus());
        server.verify();
    }

    @Test
    @DisplayName("subject_token без aud=second-backend → 403 без запроса в Keycloak")
    void exchangeWithoutAudience() {
        String token = TestTokens.sign(TestTokens.claims("test-app", List.of("account")).build(), TestTokens.KEY);
        AuthException ex = assertThrows(AuthException.class, () -> service.exchange(token, null, null));
        assertEquals(HttpStatus.FORBIDDEN, ex.getStatus());
        assertTrue(ex.getMessage().contains("Audience mapper"));
        server.verify();
    }

    @Test
    @DisplayName("Поддельный subject_token → 401 без запроса в Keycloak")
    void exchangeForgedToken() {
        String forged = TestTokens.sign(TestTokens.claims("test-app", List.of("second-backend")).build(), TestTokens.OTHER_KEY);
        assertEquals(HttpStatus.UNAUTHORIZED, assertThrows(AuthException.class, () -> service.exchange(forged, null, null)).getStatus());
        server.verify();
    }

    @Test
    @DisplayName("Неверный requested_token_type → 400")
    void exchangeInvalidRequestedType() {
        assertEquals(HttpStatus.BAD_REQUEST,
                assertThrows(AuthException.class, () -> service.exchange(TestTokens.alemToken(), null, "id_token")).getStatus());
    }

    @Test
    @DisplayName("Keycloak: Standard token exchange выключен → 400 с подсказкой")
    void exchangeNotEnabled() {
        server.expect(requestTo(TOKEN_URL)).andRespond(withStatus(HttpStatus.BAD_REQUEST)
                .contentType(MediaType.APPLICATION_JSON)
                .body("{\"error\":\"unauthorized_client\",\"error_description\":\"Standard token exchange is not enabled for the requested client\"}"));

        AuthException ex = assertThrows(AuthException.class, () -> service.exchange(TestTokens.alemToken(), null, null));
        assertEquals(HttpStatus.FORBIDDEN, ex.getStatus());
        assertTrue(ex.getMessage().contains("Capability config"));
    }

    @Test
    @DisplayName("Keycloak: invalid_client → 401")
    void exchangeInvalidClient() {
        server.expect(requestTo(TOKEN_URL)).andRespond(withStatus(HttpStatus.UNAUTHORIZED)
                .contentType(MediaType.APPLICATION_JSON)
                .body("{\"error\":\"invalid_client\",\"error_description\":\"Invalid client or Invalid client credentials\"}"));

        AuthException ex = assertThrows(AuthException.class, () -> service.exchange(TestTokens.alemToken(), null, null));
        assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatus());
        assertTrue(ex.getMessage().contains("client-secret"));
    }

    @Test
    @DisplayName("Keycloak: access_denied → 403")
    void exchangeAccessDenied() {
        server.expect(requestTo(TOKEN_URL)).andRespond(withStatus(HttpStatus.FORBIDDEN)
                .contentType(MediaType.APPLICATION_JSON)
                .body("{\"error\":\"access_denied\",\"error_description\":\"Client not allowed to exchange\"}"));

        assertEquals(HttpStatus.FORBIDDEN,
                assertThrows(AuthException.class, () -> service.exchange(TestTokens.alemToken(), null, null)).getStatus());
    }

    @Test
    @DisplayName("Keycloak недоступен → 503")
    void exchangeKeycloakDown() {
        server.expect(requestTo(TOKEN_URL)).andRespond(request -> {
            throw new ResourceAccessException("Connection refused", new IOException("Connection refused"));
        });

        AuthException ex = assertThrows(AuthException.class, () -> service.exchange(TestTokens.alemToken(), null, null));
        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, ex.getStatus());
    }

    @Test
    @DisplayName("Refresh: grant_type=refresh_token от имени second-backend")
    void refreshSuccess() {
        server.expect(requestTo(TOKEN_URL))
                .andExpect(content().formDataContains(java.util.Map.of(
                        "grant_type", "refresh_token", "refresh_token", "rt-1", "client_id", "second-backend")))
                .andRespond(withSuccess("""
                        {"access_token": "%s", "refresh_token": "rt-2", "expires_in": 300, "refresh_expires_in": 1800}
                        """.formatted(TestTokens.secondToken()), MediaType.APPLICATION_JSON));

        KeycloakTokenResponse r = service.refresh("rt-1");
        assertEquals("rt-2", r.refreshToken());
        assertNull(r.exchange());
        server.verify();
    }

    @Test
    @DisplayName("Refresh: invalid_grant → 400")
    void refreshInvalidGrant() {
        server.expect(requestTo(TOKEN_URL)).andRespond(withStatus(HttpStatus.BAD_REQUEST)
                .contentType(MediaType.APPLICATION_JSON)
                .body("{\"error\":\"invalid_grant\",\"error_description\":\"Invalid refresh token\"}"));

        assertEquals(HttpStatus.BAD_REQUEST, assertThrows(AuthException.class, () -> service.refresh("bad")).getStatus());
    }

    @Test
    @DisplayName("Introspect: парсинг активного токена")
    void introspectActive() {
        server.expect(requestTo(INTROSPECT_URL))
                .andExpect(content().formDataContains(java.util.Map.of("token", "tok", "client_id", "second-backend")))
                .andRespond(withSuccess("""
                        {"active": true, "client_id": "second-backend", "azp": "second-backend", "aud": "account",
                         "sub": "user-kc-100", "username": "aitu3", "token_type": "Bearer", "exp": 1800000000, "iat": 1799999700}
                        """, MediaType.APPLICATION_JSON));

        IntrospectionResponse r = service.introspect("tok");
        assertTrue(r.active());
        assertEquals("second-backend", r.azp());
        assertEquals(List.of("account"), r.aud());
        assertEquals("2027-01-15T08:00:00Z", r.exp());
    }

    @Test
    @DisplayName("Introspect: неактивный токен")
    void introspectInactive() {
        server.expect(requestTo(INTROSPECT_URL)).andRespond(withSuccess("{\"active\": false}", MediaType.APPLICATION_JSON));
        IntrospectionResponse r = service.introspect("tok");
        assertFalse(r.active());
        assertNull(r.clientId());
    }
}
