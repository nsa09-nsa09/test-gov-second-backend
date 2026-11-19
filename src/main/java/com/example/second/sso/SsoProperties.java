package com.example.second.sso;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Map;

/**
 * Бесшовный вход в сервисы: client, которым second меняет токен Alem,
 * и список сервисов с callback-адресом и секретом для redeem.
 */
@ConfigurationProperties(prefix = "sso")
public record SsoProperties(
        String exchangeClientId,
        String exchangeClientSecret,
        long codeTtlSeconds,
        Map<String, Service> services
) {

    public record Service(String callbackUrl, String secret) {
    }
}
