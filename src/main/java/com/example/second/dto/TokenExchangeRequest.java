package com.example.second.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Запрос на RFC 8693 Token Exchange. subject_token можно передать в теле или в заголовке Authorization: Bearer")
public record TokenExchangeRequest(
    @Schema(description = "Access token, выданный alem (Keycloak клиент test-app). Должен содержать aud = second-backend",
            example = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ...")
    @JsonProperty("subject_token")
    String subjectToken,

    @Schema(description = "Опционально: scope нового токена (через пробел). Должен быть доступен клиенту second-backend",
            example = "openid profile", nullable = true)
    String scope,

    @Schema(description = "Тип запрашиваемого токена: access_token (по умолчанию) или refresh_token. "
            + "refresh_token возвращает и access, и refresh token, если у second-backend включено "
            + "Advanced → 'Allow refresh token in Standard Token Exchange'",
            allowableValues = {"access_token", "refresh_token"}, example = "access_token", nullable = true)
    @JsonProperty("requested_token_type")
    String requestedTokenType
) {}
