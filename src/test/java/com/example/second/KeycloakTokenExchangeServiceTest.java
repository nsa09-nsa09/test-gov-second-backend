package com.example.second;

import com.example.second.exception.AuthException;
import com.example.second.service.KeycloakTokenExchangeService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

import static org.junit.jupiter.api.Assertions.*;

class KeycloakTokenExchangeServiceTest {

    @Test
    @DisplayName("Отказ при передаче пустого access_token")
    void testExchangeEmptyAccessToken() {
        KeycloakTokenExchangeService service = new KeycloakTokenExchangeService();

        AuthException ex = assertThrows(AuthException.class, () -> service.exchangeAccessToken(""));
        assertEquals(HttpStatus.BAD_REQUEST, ex.getStatus());
        assertTrue(ex.getMessage().contains("не может быть пустым"));

        AuthException ex2 = assertThrows(AuthException.class, () -> service.exchangeAccessToken(null));
        assertEquals(HttpStatus.BAD_REQUEST, ex2.getStatus());
    }
}
