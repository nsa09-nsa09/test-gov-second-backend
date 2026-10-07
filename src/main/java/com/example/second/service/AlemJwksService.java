package com.example.second.service;

import com.example.second.exception.AuthException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.util.concurrent.atomic.AtomicReference;

@Service
public class AlemJwksService {

    private static final Logger log = LoggerFactory.getLogger(AlemJwksService.class);

    @Value("${alem.jwks-url:http://localhost:8080/api/auth/jwks}")
    private String jwksUrl;

    private final RestClient restClient;
    private final AtomicReference<JWKSet> cachedJwkSet = new AtomicReference<>(null);
    private volatile long jwkSetExpiry = 0;

    public AlemJwksService() {
        this.restClient = RestClient.builder().build();
    }

    public AlemJwksService(RestClient restClient, String jwksUrl) {
        this.restClient = restClient;
        this.jwksUrl = jwksUrl;
    }

    /**
     * Получение JWKSet из кэша либо с Alem backend.
     */
    public JWKSet getJwkSet(boolean forceRefresh) {
        long now = System.currentTimeMillis();
        if (!forceRefresh && cachedJwkSet.get() != null && now < jwkSetExpiry) {
            return cachedJwkSet.get();
        }
        return reloadJwkSet();
    }

    /**
     * Поиск ключа по его ID (kid) с поддержкой ротации (принудительного обновления при отсутствии).
     */
    public JWK getKeyByKeyId(String kid) {
        if (kid == null || kid.isBlank()) {
            return null;
        }

        JWKSet jwkSet = getJwkSet(false);
        JWK key = jwkSet.getKeyByKeyId(kid);

        if (key == null) {
            log.info("Ключ с kid '{}' не найден в кэше JWKS, выполняем принудительное обновление из {}", kid, jwksUrl);
            jwkSet = getJwkSet(true);
            key = jwkSet.getKeyByKeyId(kid);
        }

        return key;
    }

    private synchronized JWKSet reloadJwkSet() {
        long now = System.currentTimeMillis();
        try {
            log.info("Загрузка публичных ключей JWKS из Alem backend ({})", jwksUrl);
            String jwksJson = restClient.get()
                    .uri(jwksUrl)
                    .retrieve()
                    .body(String.class);

            if (jwksJson == null || jwksJson.isBlank()) {
                throw new IllegalStateException("Получен пустой ответ JWKS от " + jwksUrl);
            }

            JWKSet parsed = JWKSet.parse(jwksJson);
            JWKSet publicJwkSet = parsed.toPublicJWKSet();
            cachedJwkSet.set(publicJwkSet);
            jwkSetExpiry = now + 60 * 60 * 1000; // Кэш на 1 час
            return publicJwkSet;
        } catch (Exception ex) {
            log.error("Ошибка при получении JWKS из {}: {}", jwksUrl, ex.getMessage(), ex);
            if (cachedJwkSet.get() != null) {
                log.warn("Используется ранее закэшированный набор ключей JWKS");
                return cachedJwkSet.get();
            }
            throw new AuthException(
                    "Не удалось получить публичные ключи JWKS от Alem backend (" + jwksUrl + "): " + ex.getMessage(),
                    HttpStatus.SERVICE_UNAVAILABLE
            );
        }
    }
}
