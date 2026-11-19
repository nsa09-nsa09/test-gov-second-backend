package com.example.second.service;

import com.example.second.dto.TokenCheckDto;
import com.example.second.exception.AuthException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Локальная проверка RS256 access-токенов Keycloak: подпись (JWKS realm), issuer, срок действия
 * и, опционально, authorized party (azp) — клиент, которому выдан токен.
 */
@Service
public class KeycloakTokenValidator {

    public static final String CHECK_FORMAT = "format";
    public static final String CHECK_SIGNATURE = "signature";
    public static final String CHECK_ISSUER = "issuer";
    public static final String CHECK_EXPIRATION = "expiration";
    public static final String CHECK_AUTHORIZED_PARTY = "authorized_party";

    private final KeycloakJwksService jwksService;
    private final String expectedIssuer;

    @Autowired
    public KeycloakTokenValidator(KeycloakJwksService jwksService,
                                  @Value("${keycloak.issuer:http://localhost:8180/realms/GovApps}") String expectedIssuer) {
        this.jwksService = jwksService;
        this.expectedIssuer = expectedIssuer;
    }

    /**
     * Результат всех проверок токена. claims == null, если токен не удалось распарсить.
     */
    public record ValidationReport(SignedJWT jwt, JWTClaimsSet claims, List<TokenCheckDto> checks) {
        public boolean passed() {
            return checks.stream().allMatch(TokenCheckDto::passed);
        }

        public TokenCheckDto firstFailure() {
            return checks.stream().filter(c -> !c.passed()).findFirst().orElse(null);
        }
    }

    /**
     * Проверяет токен и бросает 401 при первой неудачной проверке.
     *
     * @param requiredAzp ожидаемый azp; null — azp не проверяется
     */
    public JWTClaimsSet validate(String token, String requiredAzp) {
        if (token == null || token.isBlank()) {
            throw new AuthException("Токен не может быть пустым", HttpStatus.UNAUTHORIZED);
        }
        ValidationReport report = inspect(token, requiredAzp);
        TokenCheckDto failure = report.firstFailure();
        if (failure != null) {
            throw new AuthException("Токен отклонён (" + failure.name() + "): " + failure.detail(), HttpStatus.UNAUTHORIZED);
        }
        return report.claims();
    }

    /**
     * Выполняет все проверки без исключений (кроме недоступности JWKS — 503) и возвращает отчёт.
     */
    public ValidationReport inspect(String token, String requiredAzp) {
        List<TokenCheckDto> checks = new ArrayList<>();

        SignedJWT jwt;
        JWTClaimsSet claims;
        try {
            jwt = SignedJWT.parse(token.trim());
            claims = jwt.getJWTClaimsSet();
        } catch (ParseException e) {
            checks.add(TokenCheckDto.fail(CHECK_FORMAT, "Некорректный JWT: " + e.getMessage()));
            return new ValidationReport(null, null, checks);
        }
        checks.add(TokenCheckDto.ok(CHECK_FORMAT, "JWT распарсен"));

        checks.add(checkSignature(jwt));
        checks.add(checkIssuer(claims));
        checks.add(checkExpiration(claims));
        if (requiredAzp != null) {
            checks.add(checkAuthorizedParty(claims, requiredAzp));
        }

        return new ValidationReport(jwt, claims, checks);
    }

    private TokenCheckDto checkSignature(SignedJWT jwt) {
        JWSAlgorithm alg = jwt.getHeader().getAlgorithm();
        if (!JWSAlgorithm.RS256.equals(alg)) {
            return TokenCheckDto.fail(CHECK_SIGNATURE, "Алгоритм '" + alg + "' не поддерживается, ожидается RS256");
        }

        String kid = jwt.getHeader().getKeyID();
        JWK jwk = jwksService.getKeyByKeyId(kid);
        if (!(jwk instanceof RSAKey rsaKey)) {
            return TokenCheckDto.fail(CHECK_SIGNATURE, "RSA-ключ kid='" + kid + "' не найден в JWKS Keycloak");
        }

        try {
            if (!jwt.verify(new RSASSAVerifier(rsaKey.toRSAPublicKey()))) {
                return TokenCheckDto.fail(CHECK_SIGNATURE, "Подпись не совпадает с ключом kid='" + kid + "'");
            }
        } catch (Exception e) {
            return TokenCheckDto.fail(CHECK_SIGNATURE, "Ошибка проверки подписи: " + e.getMessage());
        }
        return TokenCheckDto.ok(CHECK_SIGNATURE, "RS256, ключ kid='" + kid + "' из JWKS Keycloak");
    }

    private TokenCheckDto checkIssuer(JWTClaimsSet claims) {
        String iss = claims.getIssuer();
        if (!expectedIssuer.equals(iss)) {
            return TokenCheckDto.fail(CHECK_ISSUER, "iss='" + iss + "', ожидается '" + expectedIssuer + "'");
        }
        return TokenCheckDto.ok(CHECK_ISSUER, "iss='" + iss + "'");
    }

    private TokenCheckDto checkExpiration(JWTClaimsSet claims) {
        Date now = new Date();
        Date exp = claims.getExpirationTime();
        if (exp == null) {
            return TokenCheckDto.fail(CHECK_EXPIRATION, "Отсутствует claim exp");
        }
        if (now.after(exp)) {
            return TokenCheckDto.fail(CHECK_EXPIRATION, "Срок действия истёк " + exp.toInstant());
        }
        Date nbf = claims.getNotBeforeTime();
        if (nbf != null && now.before(nbf)) {
            return TokenCheckDto.fail(CHECK_EXPIRATION, "Токен ещё не действует (nbf=" + nbf.toInstant() + ")");
        }
        return TokenCheckDto.ok(CHECK_EXPIRATION, "Действует до " + exp.toInstant());
    }

    private TokenCheckDto checkAuthorizedParty(JWTClaimsSet claims, String requiredAzp) {
        Object azp = claims.getClaim("azp");
        if (!requiredAzp.equals(azp)) {
            return TokenCheckDto.fail(CHECK_AUTHORIZED_PARTY,
                    "azp='" + azp + "', ожидается '" + requiredAzp + "'. Получите токен через POST /api/auth/token-exchange");
        }
        return TokenCheckDto.ok(CHECK_AUTHORIZED_PARTY, "azp='" + azp + "'");
    }
}
