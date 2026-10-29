package com.example.second.service;

import com.example.second.exception.AuthException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.util.concurrent.atomic.AtomicReference;

/**
 * Публичные ключи Keycloak realm (JWKS) для проверки RS256-подписи access-токенов.
 */
@Service
public class KeycloakJwksService {

    private static final Logger log = LoggerFactory.getLogger(KeycloakJwksService.class);

    private static final long CACHE_TTL_MILLIS = 60 * 60 * 1000; // 1 час

    private final RestClient restClient;
    private final String jwksUrl;
    private final AtomicReference<JWKSet> cachedJwkSet = new AtomicReference<>(null);
    private volatile long jwkSetExpiry = 0;

    @Autowired
    public KeycloakJwksService(
            @Value("${keycloak.jwks-url:http://localhost:8180/realms/GovApps/protocol/openid-connect/certs}") String jwksUrl) {
        this(RestClient.builder().build(), jwksUrl);
    }

    public KeycloakJwksService(RestClient restClient, String jwksUrl) {
        this.restClient = restClient;
        this.jwksUrl = jwksUrl;
    }

    /**
     * Поиск ключа по kid. Если ключа нет в кэше (ротация ключей в Keycloak), JWKS перезагружается.
     */
    public JWK getKeyByKeyId(String kid) {
        if (kid == null || kid.isBlank()) {
            return null;
        }

        JWK key = getJwkSet(false).getKeyByKeyId(kid);
        if (key == null) {
            log.info("Ключ с kid '{}' не найден в кэше JWKS Keycloak, обновляем из {}", kid, jwksUrl);
            key = getJwkSet(true).getKeyByKeyId(kid);
        }
        return key;
    }

    public String getJwksUrl() {
        return jwksUrl;
    }

    private JWKSet getJwkSet(boolean forceRefresh) {
        JWKSet cached = cachedJwkSet.get();
        if (!forceRefresh && cached != null && System.currentTimeMillis() < jwkSetExpiry) {
            return cached;
        }
        return reloadJwkSet();
    }

    private synchronized JWKSet reloadJwkSet() {
        try {
            log.info("Загрузка JWKS Keycloak ({})", jwksUrl);
            String jwksJson = restClient.get()
                    .uri(jwksUrl)
                    .retrieve()
                    .body(String.class);

            if (jwksJson == null || jwksJson.isBlank()) {
                throw new IllegalStateException("Пустой ответ JWKS от " + jwksUrl);
            }

            JWKSet publicJwkSet = JWKSet.parse(jwksJson).toPublicJWKSet();
            cachedJwkSet.set(publicJwkSet);
            jwkSetExpiry = System.currentTimeMillis() + CACHE_TTL_MILLIS;
            return publicJwkSet;
        } catch (Exception ex) {
            log.error("Ошибка при получении JWKS Keycloak из {}: {}", jwksUrl, ex.getMessage());
            if (cachedJwkSet.get() != null) {
                log.warn("Используется ранее закэшированный JWKS Keycloak");
                return cachedJwkSet.get();
            }
            throw new AuthException(
                    "Не удалось получить JWKS Keycloak (" + jwksUrl + "): " + ex.getMessage(),
                    HttpStatus.SERVICE_UNAVAILABLE
            );
        }
    }
}
