package com.example.second.sso;

import com.example.second.exception.AuthException;
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
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Бесшовный вход в сервис (гайд ai-gov-sso-plan.pdf, раздел 3):
 * start меняет токен Alem на токен с aud = сервис и прячет его под одноразовым кодом,
 * redeem отдаёт сервису данные пользователя и этот токен по коду и секрету сервиса.
 */
@Service
public class SsoService {

    private static final Logger log = LoggerFactory.getLogger(SsoService.class);

    private static final String GRANT_TYPE_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
    private static final String TOKEN_TYPE_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token";

    private final RestClient restClient;
    private final SsoProperties properties;
    private final String tokenUrl;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Map<String, PendingCode> codes = new ConcurrentHashMap<>();

    @Autowired
    public SsoService(SsoProperties properties,
                      @Value("${keycloak.server-url:http://localhost:18630}") String serverUrl,
                      @Value("${keycloak.realm:GovApps}") String realm) {
        this(RestClient.builder().build(), properties, serverUrl, realm, Clock.systemUTC());
    }

    public SsoService(RestClient restClient, SsoProperties properties, String serverUrl, String realm, Clock clock) {
        this.restClient = restClient;
        this.properties = properties;
        this.tokenUrl = String.format("%s/realms/%s/protocol/openid-connect/token", serverUrl, realm);
        this.clock = clock;
    }

    public String start(String serviceId, String alemToken) {
        SsoProperties.Service service = properties.services().get(serviceId);
        if (service == null) {
            throw new AuthException("Неизвестный сервис: " + serviceId, HttpStatus.NOT_FOUND);
        }
        if (alemToken == null || alemToken.isBlank()) {
            throw new AuthException("Нужен заголовок Authorization: Bearer <токен Alem>", HttpStatus.UNAUTHORIZED);
        }
        String serviceToken = exchange(serviceId, alemToken);
        String code = newCode();
        codes.put(code, new PendingCode(serviceId, serviceToken, clock.instant().plusSeconds(properties.codeTtlSeconds())));
        log.info("SSO: выдан код для сервиса {}", serviceId);
        return service.callbackUrl() + "?code=" + code;
    }

    public SsoRedeemResponse redeem(String serviceSecret, String code) {
        String serviceId = serviceBySecret(serviceSecret);
        PendingCode pending = code == null ? null : codes.remove(code);
        if (pending == null || clock.instant().isAfter(pending.expiresAt())) {
            log.warn("SSO: сервис {} предъявил неизвестный, использованный или просроченный код", serviceId);
            throw new AuthException("Код неизвестен, уже использован или просрочен", HttpStatus.BAD_REQUEST);
        }
        if (!pending.serviceId().equals(serviceId)) {
            log.warn("SSO: сервис {} предъявил код, выданный для {}", serviceId, pending.serviceId());
            throw new AuthException("Код выдан для другого сервиса", HttpStatus.FORBIDDEN);
        }
        JWTClaimsSet claims = claimsOf(pending.accessToken());
        log.info("SSO: сервис {} получил пользователя {}", serviceId, claims.getSubject());
        return new SsoRedeemResponse(
                claims.getSubject(),
                stringClaim(claims, "name"),
                stringClaim(claims, "email"),
                pending.accessToken());
    }

    private String exchange(String serviceId, String alemToken) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", GRANT_TYPE_TOKEN_EXCHANGE);
        form.add("client_id", properties.exchangeClientId());
        form.add("client_secret", properties.exchangeClientSecret());
        form.add("subject_token", alemToken);
        form.add("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN);
        form.add("requested_token_type", TOKEN_TYPE_ACCESS_TOKEN);
        form.add("audience", serviceId);
        form.add("scope", "openid email profile " + serviceId + "-audience");
        try {
            String body = restClient.post()
                    .uri(tokenUrl)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .retrieve()
                    .body(String.class);
            JsonNode accessToken = objectMapper.readTree(body).get("access_token");
            if (accessToken == null || accessToken.asText().isBlank()) {
                throw new AuthException("Keycloak не вернул access_token для " + serviceId, HttpStatus.BAD_GATEWAY);
            }
            return accessToken.asText();
        } catch (RestClientResponseException e) {
            log.warn("SSO: Keycloak отклонил обмен для {}: {}", serviceId, e.getResponseBodyAsString());
            HttpStatus status = e.getStatusCode().value() == 400 ? HttpStatus.UNAUTHORIZED : HttpStatus.BAD_GATEWAY;
            throw new AuthException("Keycloak отклонил обмен токена для " + serviceId + ": "
                    + e.getResponseBodyAsString(), status);
        } catch (AuthException e) {
            throw e;
        } catch (Exception e) {
            throw new AuthException("Не удалось обменять токен для " + serviceId + ": " + e.getMessage(),
                    HttpStatus.BAD_GATEWAY);
        }
    }

    private String serviceBySecret(String secret) {
        if (secret != null && !secret.isBlank()) {
            byte[] given = secret.getBytes(StandardCharsets.UTF_8);
            for (Map.Entry<String, SsoProperties.Service> entry : properties.services().entrySet()) {
                byte[] expected = entry.getValue().secret().getBytes(StandardCharsets.UTF_8);
                if (MessageDigest.isEqual(given, expected)) {
                    return entry.getKey();
                }
            }
        }
        throw new AuthException("Неверный секрет сервиса", HttpStatus.UNAUTHORIZED);
    }

    private String newCode() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static JWTClaimsSet claimsOf(String token) {
        try {
            return SignedJWT.parse(token).getJWTClaimsSet();
        } catch (ParseException e) {
            throw new AuthException("Keycloak вернул нечитаемый токен: " + e.getMessage(), HttpStatus.BAD_GATEWAY);
        }
    }

    private static String stringClaim(JWTClaimsSet claims, String name) {
        Object value = claims.getClaim(name);
        return value == null ? null : value.toString();
    }

    private record PendingCode(String serviceId, String accessToken, Instant expiresAt) {
    }
}
