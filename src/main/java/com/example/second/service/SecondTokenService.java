package com.example.second.service;

import com.example.second.dto.TokenExchangeResponse;
import com.example.second.dto.UserInfoDto;
import com.example.second.exception.AuthException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.*;

@Service
public class SecondTokenService {

    private static final Logger log = LoggerFactory.getLogger(SecondTokenService.class);

    @Value("${jwt.secret:second-backend-super-secret-key-that-is-at-least-256-bits-long-for-hmac-sha256}")
    private String secret;

    @Value("${jwt.issuer:second-backend}")
    private String issuer;

    @Value("${jwt.audience:second-service}")
    private String audience;

    @Value("${jwt.access-token-expiration-seconds:900}")
    private long accessExpirySeconds;

    @Value("${jwt.refresh-token-expiration-seconds:604800}")
    private long refreshExpirySeconds;

    public SecondTokenService() {}

    public SecondTokenService(String secret, String issuer, String audience, long accessExpirySeconds, long refreshExpirySeconds) {
        this.secret = secret;
        this.issuer = issuer;
        this.audience = audience;
        this.accessExpirySeconds = accessExpirySeconds;
        this.refreshExpirySeconds = refreshExpirySeconds;
    }

    /**
     * Выпуск пары токенов (Access и Refresh) для верифицированного пользователя.
     */
    public TokenExchangeResponse issueTokens(UserInfoDto user) {
        String accessToken = generateToken(user, "access", accessExpirySeconds);
        String refreshToken = generateToken(user, "refresh", refreshExpirySeconds);

        return new TokenExchangeResponse(
                accessToken,
                refreshToken,
                "Bearer",
                accessExpirySeconds,
                refreshExpirySeconds,
                user
        );
    }

    /**
     * Обновление пары токенов по валидному refresh-токену Second Backend.
     */
    public TokenExchangeResponse refresh(String refreshTokenString) {
        JWTClaimsSet claims = validateToken(refreshTokenString, "refresh");
        UserInfoDto user = extractUser(claims);

        String newAccessToken = generateToken(user, "access", accessExpirySeconds);
        // Ротация refresh токена
        String newRefreshToken = generateToken(user, "refresh", refreshExpirySeconds);

        log.info("Токены Second Backend успешно обновлены для пользователя '{}'", user.username());

        return new TokenExchangeResponse(
                newAccessToken,
                newRefreshToken,
                "Bearer",
                accessExpirySeconds,
                refreshExpirySeconds,
                user
        );
    }

    /**
     * Валидация токена Second Backend по секретному ключу и проверке срока действия.
     */
    public JWTClaimsSet validateToken(String tokenString, String expectedType) {
        if (tokenString == null || tokenString.isBlank()) {
            throw new AuthException("Токен не может быть пустым", HttpStatus.UNAUTHORIZED);
        }

        try {
            SignedJWT signedJWT = SignedJWT.parse(tokenString.trim());
            MACVerifier verifier = new MACVerifier(secret.getBytes(StandardCharsets.UTF_8));

            if (!signedJWT.verify(verifier)) {
                throw new AuthException("Неверная подпись токена Second Backend", HttpStatus.UNAUTHORIZED);
            }

            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            Date now = new Date();

            Date exp = claims.getExpirationTime();
            if (exp != null && now.after(exp)) {
                throw new AuthException("Срок действия токена Second Backend истек (" + exp + ")", HttpStatus.UNAUTHORIZED);
            }

            Date nbf = claims.getNotBeforeTime();
            if (nbf != null && now.before(nbf)) {
                throw new AuthException("Токен Second Backend еще не вступил в силу", HttpStatus.UNAUTHORIZED);
            }

            if (expectedType != null) {
                String tokenType = claims.getStringClaim("token_type");
                if (!expectedType.equalsIgnoreCase(tokenType)) {
                    throw new AuthException("Ожидался токен типа '" + expectedType + "', но получен '" + tokenType + "'", HttpStatus.UNAUTHORIZED);
                }
            }

            return claims;
        } catch (AuthException ae) {
            throw ae;
        } catch (Exception e) {
            log.error("Ошибка при валидации токена Second Backend: {}", e.getMessage(), e);
            throw new AuthException("Невалидный токен Second Backend: " + e.getMessage(), HttpStatus.UNAUTHORIZED);
        }
    }

    /**
     * Извлечение информации о пользователе из клеймов токена Second Backend.
     */
    public UserInfoDto extractUser(JWTClaimsSet claims) {
        String sub = claims.getSubject();
        String username = null;
        String email = null;
        String name = null;
        List<String> roles = new ArrayList<>();

        try {
            username = claims.getStringClaim("preferred_username");
            if (username == null || username.isBlank()) {
                username = claims.getStringClaim("username");
            }
            email = claims.getStringClaim("email");
            name = claims.getStringClaim("name");

            List<?> rolesClaim = claims.getStringListClaim("roles");
            if (rolesClaim != null) {
                for (Object r : rolesClaim) {
                    if (r != null) roles.add(r.toString());
                }
            }
        } catch (Exception e) {
            log.warn("Не удалось прочитать клеймы токена: {}", e.getMessage());
        }

        if (username == null || username.isBlank()) {
            username = sub;
        }

        return new UserInfoDto(sub, username, email, name, roles);
    }

    private String generateToken(UserInfoDto user, String tokenType, long durationSeconds) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + durationSeconds * 1000);

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .issuer(issuer)
                .audience(audience)
                .subject(user.sub())
                .issueTime(now)
                .expirationTime(expiry)
                .claim("token_type", tokenType)
                .claim("preferred_username", user.username())
                .claim("username", user.username());

        if (user.email() != null && !user.email().isBlank()) {
            builder.claim("email", user.email());
        }
        if (user.name() != null && !user.name().isBlank()) {
            builder.claim("name", user.name());
        }
        if (user.roles() != null && !user.roles().isEmpty()) {
            builder.claim("roles", user.roles());
        }

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader(JWSAlgorithm.HS256),
                builder.build()
        );

        try {
            MACSigner signer = new MACSigner(secret.getBytes(StandardCharsets.UTF_8));
            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (Exception e) {
            log.error("Ошибка при подписи токена: {}", e.getMessage(), e);
            throw new AuthException("Не удалось сгенерировать токен: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
