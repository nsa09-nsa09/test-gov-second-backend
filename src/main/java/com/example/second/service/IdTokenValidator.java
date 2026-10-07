package com.example.second.service;

import com.example.second.dto.UserInfoDto;
import com.example.second.exception.AuthException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.util.*;

@Service
public class IdTokenValidator {

    private static final Logger log = LoggerFactory.getLogger(IdTokenValidator.class);

    private final AlemJwksService alemJwksService;

    public IdTokenValidator(AlemJwksService alemJwksService) {
        this.alemJwksService = alemJwksService;
    }

    /**
     * Валидация ID-токена по JWKS ключам Alem backend и извлечение информации о пользователе.
     */
    public UserInfoDto validateAndExtractUser(String idTokenString) {
        if (idTokenString == null || idTokenString.isBlank()) {
            throw new AuthException("ID токен не может быть пустым", HttpStatus.BAD_REQUEST);
        }

        SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(idTokenString.trim());
        } catch (ParseException e) {
            throw new AuthException("Некорректный формат JWT токена: " + e.getMessage(), HttpStatus.BAD_REQUEST);
        }

        JWSHeader header = signedJWT.getHeader();
        String kid = header.getKeyID();
        String alg = header.getAlgorithm() != null ? header.getAlgorithm().getName() : "UNKNOWN";

        if (kid == null || kid.isBlank()) {
            throw new AuthException("В заголовке ID-токена отсутствует идентификатор ключа (kid)", HttpStatus.UNAUTHORIZED);
        }

        JWK jwk = alemJwksService.getKeyByKeyId(kid);
        if (jwk == null) {
            throw new AuthException("Ключ с kid '" + kid + "' не найден в публичном наборе JWKS Alem backend", HttpStatus.UNAUTHORIZED);
        }

        if (!(jwk instanceof RSAKey rsaKey)) {
            throw new AuthException("Тип ключа '" + jwk.getKeyType() + "' не поддерживается (ожидается RSA)", HttpStatus.UNAUTHORIZED);
        }

        try {
            RSASSAVerifier verifier = new RSASSAVerifier(rsaKey.toRSAPublicKey());
            boolean signatureValid = signedJWT.verify(verifier);

            if (!signatureValid) {
                throw new AuthException("Криптографическая подпись ID-токена не совпадает (поддельный или поврежденный токен)", HttpStatus.UNAUTHORIZED);
            }

            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            Date now = new Date();

            // Проверка exp (срок действия)
            Date expirationTime = claimsSet.getExpirationTime();
            if (expirationTime != null && now.after(expirationTime)) {
                throw new AuthException("Срок действия ID-токена истек (" + expirationTime + ")", HttpStatus.UNAUTHORIZED);
            }

            // Проверка nbf (not before)
            Date notBeforeTime = claimsSet.getNotBeforeTime();
            if (notBeforeTime != null && now.before(notBeforeTime)) {
                throw new AuthException("ID-токен еще не вступил в силу (not before " + notBeforeTime + ")", HttpStatus.UNAUTHORIZED);
            }

            String sub = claimsSet.getSubject();
            if (sub == null || sub.isBlank()) {
                throw new AuthException("В ID-токене отсутствует обязательный клейм subject (sub)", HttpStatus.UNAUTHORIZED);
            }

            String username = claimsSet.getStringClaim("preferred_username");
            if (username == null || username.isBlank()) {
                username = claimsSet.getStringClaim("username");
            }
            if (username == null || username.isBlank()) {
                username = sub;
            }

            String email = claimsSet.getStringClaim("email");
            String name = claimsSet.getStringClaim("name");
            if (name == null || name.isBlank()) {
                String givenName = claimsSet.getStringClaim("given_name");
                String familyName = claimsSet.getStringClaim("family_name");
                if (givenName != null || familyName != null) {
                    name = ((givenName != null ? givenName : "") + " " + (familyName != null ? familyName : "")).trim();
                }
            }

            List<String> roles = extractRoles(claimsSet);

            log.info("ID-токен успешно верифицирован через JWKS Alem для пользователя '{}' (sub={})", username, sub);

            return new UserInfoDto(sub, username, email, name, roles);
        } catch (AuthException ae) {
            throw ae;
        } catch (Exception e) {
            log.error("Ошибка при проверке подписи ID-токена (kid={}): {}", kid, e.getMessage(), e);
            throw new AuthException("Ошибка верификации подписи ID-токена: " + e.getMessage(), HttpStatus.UNAUTHORIZED);
        }
    }

    @SuppressWarnings("unchecked")
    private List<String> extractRoles(JWTClaimsSet claimsSet) {
        List<String> roles = new ArrayList<>();
        try {
            Object realmAccessObj = claimsSet.getClaim("realm_access");
            if (realmAccessObj instanceof Map<?, ?> realmAccessMap) {
                Object rolesObj = realmAccessMap.get("roles");
                if (rolesObj instanceof List<?> rolesList) {
                    for (Object r : rolesList) {
                        if (r != null) {
                            roles.add(r.toString());
                        }
                    }
                }
            }

            // Дополнительно проверяем roles напрямую
            Object directRoles = claimsSet.getClaim("roles");
            if (directRoles instanceof List<?> directList) {
                for (Object r : directList) {
                    if (r != null && !roles.contains(r.toString())) {
                        roles.add(r.toString());
                    }
                }
            }
        } catch (Exception e) {
            log.warn("Не удалось извлечь роли из токена: {}", e.getMessage());
        }
        return roles;
    }
}
