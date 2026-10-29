package com.example.second.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

@Schema(description = "Запрос на обмен id_token на HS256-токены second-backend")
public record ExchangeTokenRequest(
    @NotBlank(message = "id_token не может быть пустым")
    @Schema(description = "id_token из ответа alem /api/auth/login", example = "eyJhbGciOiJSUzI1NiIs...")
    @JsonProperty("id_token")
    String idToken
) {}
