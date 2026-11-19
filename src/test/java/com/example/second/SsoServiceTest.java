package com.example.second;

import com.example.second.exception.AuthException;
import com.example.second.sso.SsoProperties;
import com.example.second.sso.SsoRedeemResponse;
import com.example.second.sso.SsoService;
import com.example.second.support.TestTokens;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withBadRequest;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

class SsoServiceTest {

    private static final String TOKEN_URL = "http://kc/realms/GovApps/protocol/openid-connect/token";

    private final MutableClock clock = new MutableClock(Instant.parse("2026-11-20T10:00:00Z"));
    private MockRestServiceServer server;
    private SsoService service;

    @BeforeEach
    void setUp() {
        SsoProperties properties = new SsoProperties("aitugovworkspace-backend", "exchange-secret", 60, Map.of(
                "ai-gov", new SsoProperties.Service("http://ai/sso/callback", "ai-secret"),
                "eotinish", new SsoProperties.Service("http://eo/sso/callback", "eo-secret")));
        RestClient.Builder builder = RestClient.builder();
        server = MockRestServiceServer.bindTo(builder).build();
        service = new SsoService(builder.build(), properties, "http://kc", "GovApps", clock);
    }

    @Test
    @DisplayName("start меняет токен с audience сервиса, redeem отдаёт пользователя один раз")
    void startAndRedeemOnce() {
        String serviceToken = serviceToken("ai-gov");
        server.expect(requestTo(TOKEN_URL))
                .andExpect(method(HttpMethod.POST))
                .andExpect(content().formDataContains(Map.of(
                        "client_id", "aitugovworkspace-backend",
                        "audience", "ai-gov",
                        "scope", "openid email profile ai-gov-audience")))
                .andRespond(withSuccess("{\"access_token\":\"" + serviceToken + "\"}", MediaType.APPLICATION_JSON));

        String url = service.start("ai-gov", TestTokens.alemToken());
        assertThat(url).startsWith("http://ai/sso/callback?code=");
        String code = url.substring(url.indexOf("code=") + 5);

        SsoRedeemResponse user = service.redeem("ai-secret", code);
        assertThat(user.userId()).isEqualTo("user-1");
        assertThat(user.accessToken()).isEqualTo(serviceToken);

        assertThatThrownBy(() -> service.redeem("ai-secret", code))
                .isInstanceOf(AuthException.class)
                .satisfies(e -> assertThat(((AuthException) e).getStatus()).isEqualTo(HttpStatus.BAD_REQUEST));
    }

    @Test
    @DisplayName("Код старше 60 секунд не принимается")
    void expiredCodeIsRejected() {
        String code = issueCode("ai-gov");
        clock.advanceSeconds(61);

        assertThatThrownBy(() -> service.redeem("ai-secret", code))
                .isInstanceOf(AuthException.class)
                .satisfies(e -> assertThat(((AuthException) e).getStatus()).isEqualTo(HttpStatus.BAD_REQUEST));
    }

    @Test
    @DisplayName("Код другого сервиса и неверный секрет отклоняются")
    void foreignCodeAndWrongSecretAreRejected() {
        String code = issueCode("ai-gov");

        assertThatThrownBy(() -> service.redeem("wrong", code))
                .satisfies(e -> assertThat(((AuthException) e).getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED));
        assertThatThrownBy(() -> service.redeem("eo-secret", code))
                .satisfies(e -> assertThat(((AuthException) e).getStatus()).isEqualTo(HttpStatus.FORBIDDEN));
    }

    @Test
    @DisplayName("Отказ Keycloak в обмене даёт 401 с причиной")
    void keycloakRejectionIsReported() {
        server.expect(requestTo(TOKEN_URL))
                .andRespond(withBadRequest().body("{\"error\":\"invalid_request\",\"error_description\":\"Requested audience not available: ai-gov\"}"));

        assertThatThrownBy(() -> service.start("ai-gov", TestTokens.alemToken()))
                .isInstanceOf(AuthException.class)
                .hasMessageContaining("Requested audience not available")
                .satisfies(e -> assertThat(((AuthException) e).getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED));
    }

    @Test
    @DisplayName("Неизвестный сервис — 404")
    void unknownServiceIsRejected() {
        assertThatThrownBy(() -> service.start("unknown", TestTokens.alemToken()))
                .satisfies(e -> assertThat(((AuthException) e).getStatus()).isEqualTo(HttpStatus.NOT_FOUND));
    }

    private String issueCode(String serviceId) {
        server.expect(requestTo(TOKEN_URL))
                .andRespond(withSuccess("{\"access_token\":\"" + serviceToken(serviceId) + "\"}", MediaType.APPLICATION_JSON));
        String url = service.start(serviceId, TestTokens.alemToken());
        return url.substring(url.indexOf("code=") + 5);
    }

    private static String serviceToken(String audience) {
        return TestTokens.sign(TestTokens.claims("aitugovworkspace-backend", List.of(audience))
                .subject("user-1")
                .claim("name", "Sso Test")
                .claim("email", "sso_test@example.com")
                .build(), TestTokens.KEY);
    }

    private static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        void advanceSeconds(long seconds) {
            now = now.plusSeconds(seconds);
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
