package com.example.second.support;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Генерация RS256-токенов в формате Keycloak для тестов.
 */
public final class TestTokens {

    public static final String ISSUER = "http://localhost:8180/realms/GovApps";
    public static final String KID = "kc-test-key-1";

    public static final RSAKey KEY;
    public static final RSAKey OTHER_KEY;

    static {
        try {
            KEY = new RSAKeyGenerator(2048).keyID(KID).generate();
            OTHER_KEY = new RSAKeyGenerator(2048).keyID(KID).generate();
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private TestTokens() {}

    public static JWTClaimsSet.Builder claims(String azp, List<String> aud) {
        return new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject("user-kc-100")
                .audience(aud)
                .jwtID("jti-" + azp)
                .claim("azp", azp)
                .claim("typ", "Bearer")
                .claim("scope", "profile email")
                .claim("preferred_username", "aitu3")
                .claim("email", "aitu3@example.com")
                .claim("name", "Aitu User")
                .claim("realm_access", Map.of("roles", List.of("user")))
                .claim("resource_access", Map.of("second-backend", Map.of("roles", List.of("reader"))))
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 300_000));
    }

    /** Токен alem: azp=test-app, aud содержит second-backend. */
    public static String alemToken() {
        return sign(claims("test-app", List.of("second-backend", "account")).build(), KEY);
    }

    /** Токен после обмена: azp=second-backend. */
    public static String secondToken() {
        return sign(claims("second-backend", List.of("account")).build(), KEY);
    }

    public static String sign(JWTClaimsSet claims, RSAKey key) {
        try {
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(), claims);
            jwt.sign(new RSASSASigner(key));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
