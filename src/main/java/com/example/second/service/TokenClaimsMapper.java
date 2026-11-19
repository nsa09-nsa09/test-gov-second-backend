package com.example.second.service;

import com.example.second.dto.TokenSummaryDto;
import com.example.second.dto.UserInfoDto;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Преобразование claims Keycloak-токенов в DTO ответа.
 */
public final class TokenClaimsMapper {

    private TokenClaimsMapper() {}

    /**
     * Краткая сводка claims без проверки подписи. Для невалидного JWT возвращает null.
     */
    public static TokenSummaryDto summarize(String token) {
        try {
            return summarize(SignedJWT.parse(token.trim()).getJWTClaimsSet());
        } catch (Exception e) {
            return null;
        }
    }

    public static TokenSummaryDto summarize(JWTClaimsSet claims) {
        return new TokenSummaryDto(
                claims.getIssuer(),
                stringClaim(claims, "azp"),
                claims.getAudience(),
                claims.getSubject(),
                stringClaim(claims, "preferred_username"),
                claims.getJWTID(),
                stringClaim(claims, "typ"),
                stringClaim(claims, "scope"),
                isoDate(claims.getIssueTime()),
                isoDate(claims.getExpirationTime())
        );
    }

    /**
     * Пользователь из claims: realm-роли + роли клиента clientId из resource_access.
     */
    public static UserInfoDto extractUser(JWTClaimsSet claims, String clientId) {
        String sub = claims.getSubject();
        String username = stringClaim(claims, "preferred_username");
        if (username == null || username.isBlank()) {
            username = stringClaim(claims, "username");
        }
        if (username == null || username.isBlank()) {
            username = sub;
        }

        return new UserInfoDto(sub, username, stringClaim(claims, "email"), stringClaim(claims, "name"),
                extractRoles(claims, clientId));
    }

    public static String isoDate(Date date) {
        return date != null ? date.toInstant().toString() : null;
    }

    private static List<String> extractRoles(JWTClaimsSet claims, String clientId) {
        List<String> roles = new ArrayList<>();
        addRoles(roles, claims.getClaim("realm_access"));
        if (claims.getClaim("resource_access") instanceof Map<?, ?> resourceAccess && clientId != null) {
            addRoles(roles, resourceAccess.get(clientId));
        }
        return roles;
    }

    private static void addRoles(List<String> target, Object accessClaim) {
        if (accessClaim instanceof Map<?, ?> access && access.get("roles") instanceof List<?> list) {
            for (Object role : list) {
                if (role != null && !target.contains(role.toString())) {
                    target.add(role.toString());
                }
            }
        }
    }

    private static String stringClaim(JWTClaimsSet claims, String name) {
        Object value = claims.getClaim(name);
        return value != null ? value.toString() : null;
    }
}
