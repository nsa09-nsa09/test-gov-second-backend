package com.example.second;

import com.example.second.dto.UserInfoDto;
import com.example.second.exception.AuthException;
import com.example.second.service.AlemJwksService;
import com.example.second.service.IdTokenValidator;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

class IdTokenValidatorTest {

    private static RSAKey rsaJWK;
    private static RSAKey rsaPublicJWK;

    @BeforeAll
    static void initKeys() throws Exception {
        rsaJWK = new RSAKeyGenerator(2048)
                .keyID("alem-test-key-1")
                .generate();
        rsaPublicJWK = rsaJWK.toPublicJWK();
    }

    private String createIdToken(String kid, Date exp, RSAKey signingKey) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(kid)
                .build();

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("http://localhost:8180/realms/GovApps")
                .subject("user-kc-100")
                .claim("preferred_username", "aitu3")
                .claim("email", "aitu3@example.com")
                .claim("name", "Aitu User")
                .claim("realm_access", Map.of("roles", List.of("offline_access", "uma_authorization", "user")))
                .issueTime(new Date())
                .expirationTime(exp)
                .build();

        SignedJWT signedJWT = new SignedJWT(header, claims);
        signedJWT.sign(new RSASSASigner(signingKey));
        return signedJWT.serialize();
    }

    @Test
    @DisplayName("Успешная валидация валидного ID-токена через JWKS")
    void testValidateValidIdToken() throws Exception {
        AlemJwksService jwksService = Mockito.mock(AlemJwksService.class);
        when(jwksService.getKeyByKeyId("alem-test-key-1")).thenReturn(rsaPublicJWK);

        IdTokenValidator validator = new IdTokenValidator(jwksService);

        Date validExp = new Date(System.currentTimeMillis() + 3600 * 1000);
        String idToken = createIdToken("alem-test-key-1", validExp, rsaJWK);

        UserInfoDto user = validator.validateAndExtractUser(idToken);

        assertNotNull(user);
        assertEquals("user-kc-100", user.sub());
        assertEquals("aitu3", user.username());
        assertEquals("aitu3@example.com", user.email());
        assertEquals("Aitu User", user.name());
        assertTrue(user.roles().contains("user"));
    }

    @Test
    @DisplayName("Отказ при истекшем сроке действия ID-токена")
    void testRejectExpiredIdToken() throws Exception {
        AlemJwksService jwksService = Mockito.mock(AlemJwksService.class);
        when(jwksService.getKeyByKeyId("alem-test-key-1")).thenReturn(rsaPublicJWK);

        IdTokenValidator validator = new IdTokenValidator(jwksService);

        Date expired = new Date(System.currentTimeMillis() - 10000);
        String idToken = createIdToken("alem-test-key-1", expired, rsaJWK);

        AuthException ex = assertThrows(AuthException.class, () -> validator.validateAndExtractUser(idToken));
        assertTrue(ex.getMessage().contains("истек"));
    }

    @Test
    @DisplayName("Отказ при неверной подписи (подписан другим RSA ключом)")
    void testRejectInvalidSignature() throws Exception {
        RSAKey anotherKey = new RSAKeyGenerator(2048).keyID("alem-test-key-1").generate();

        AlemJwksService jwksService = Mockito.mock(AlemJwksService.class);
        when(jwksService.getKeyByKeyId("alem-test-key-1")).thenReturn(rsaPublicJWK);

        IdTokenValidator validator = new IdTokenValidator(jwksService);

        Date validExp = new Date(System.currentTimeMillis() + 3600 * 1000);
        String idToken = createIdToken("alem-test-key-1", validExp, anotherKey);

        AuthException ex = assertThrows(AuthException.class, () -> validator.validateAndExtractUser(idToken));
        assertTrue(ex.getMessage().contains("не совпадает") || ex.getMessage().contains("подпись"));
    }

    @Test
    @DisplayName("Отказ при неизвестном идентификаторе ключа (kid)")
    void testRejectUnknownKid() throws Exception {
        AlemJwksService jwksService = Mockito.mock(AlemJwksService.class);
        when(jwksService.getKeyByKeyId("unknown-kid")).thenReturn(null);

        IdTokenValidator validator = new IdTokenValidator(jwksService);

        Date validExp = new Date(System.currentTimeMillis() + 3600 * 1000);
        String idToken = createIdToken("unknown-kid", validExp, rsaJWK);

        AuthException ex = assertThrows(AuthException.class, () -> validator.validateAndExtractUser(idToken));
        assertTrue(ex.getMessage().contains("не найден в публичном наборе JWKS"));
    }
}
