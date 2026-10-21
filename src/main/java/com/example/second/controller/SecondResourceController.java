package com.example.second.controller;

import com.example.second.dto.ApiResponse;
import com.example.second.dto.UserInfoDto;
import com.example.second.exception.AuthException;
import com.example.second.service.IdTokenValidator;
import com.example.second.service.SecondTokenService;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/second")
public class SecondResourceController {

    private final SecondTokenService secondTokenService;
    private final IdTokenValidator idTokenValidator;

    public SecondResourceController(SecondTokenService secondTokenService) {
        this(secondTokenService, null);
    }

    @Autowired
    public SecondResourceController(SecondTokenService secondTokenService, IdTokenValidator idTokenValidator) {
        this.secondTokenService = secondTokenService;
        this.idTokenValidator = idTokenValidator;
    }

    /**
     * Защищенный эндпоинт Second Backend, требующий валидный Access Token Second Backend.
     * Поддерживает как собственные HMAC (HS256) токены, так и Keycloak RS256 токены после Token Exchange.
     */
    @GetMapping("/me")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getMe(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new AuthException("Отсутствует или некорректен заголовок Authorization: ожидается 'Bearer <token>'",
                    HttpStatus.UNAUTHORIZED);
        }

        String token = authHeader.substring(7).trim();
        UserInfoDto user;
        String issuer;
        List<String> audience;
        String expiresAt;

        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            if (signedJWT.getHeader().getAlgorithm() != null && signedJWT.getHeader().getAlgorithm().getName().startsWith("RS")) {
                if (idTokenValidator != null) {
                    user = idTokenValidator.validateAndExtractUser(token);
                    JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
                    issuer = claims.getIssuer();
                    audience = claims.getAudience();
                    expiresAt = claims.getExpirationTime() != null ? claims.getExpirationTime().toString() : "—";
                } else {
                    throw new AuthException("RSA валидатор недоступен", HttpStatus.INTERNAL_SERVER_ERROR);
                }
            } else {
                JWTClaimsSet claims = secondTokenService.validateToken(token, "access");
                user = secondTokenService.extractUser(claims);
                issuer = claims.getIssuer();
                audience = claims.getAudience();
                expiresAt = claims.getExpirationTime() != null ? claims.getExpirationTime().toString() : "—";
            }
        } catch (AuthException ae) {
            throw ae;
        } catch (Exception e) {
            // Fallback to secondTokenService in case token format is mocked in tests
            JWTClaimsSet claims = secondTokenService.validateToken(token, "access");
            user = secondTokenService.extractUser(claims);
            issuer = claims.getIssuer();
            audience = claims.getAudience();
            expiresAt = claims.getExpirationTime() != null ? claims.getExpirationTime().toString() : "—";
        }

        Map<String, Object> data = Map.of(
                "user", user,
                "service", "second-backend",
                "issuer", issuer != null ? issuer : "—",
                "audience", audience != null ? audience : List.of(),
                "expires_at", expiresAt,
                "authorized_at", Instant.now().toString()
        );

        return ResponseEntity.ok(ApiResponse.ok("Успешная авторизация в Second Backend", data));
    }
}
