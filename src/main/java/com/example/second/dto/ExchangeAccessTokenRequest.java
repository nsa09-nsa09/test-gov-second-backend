package com.example.second.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

@Schema(description = "[Deprecated] Запрос на обмен access token alem")
public record ExchangeAccessTokenRequest(
    @NotBlank(message = "access_token не может быть пустым")
    @Schema(description = "Access token от alem", example = "eyJhbGciOiJSUzI1NiIs...")
    @JsonProperty("access_token")
    String accessToken
) {}
