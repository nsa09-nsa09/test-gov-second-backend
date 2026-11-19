package com.example.second.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

@Schema(description = "Запрос на обновление токенов по refresh_token")
public record RefreshTokenRequest(
    @NotBlank(message = "refresh_token не может быть пустым")
    @Schema(description = "Refresh token", example = "eyJhbGciOiJIUzUxMiIs...")
    @JsonProperty("refresh_token")
    String refreshToken
) {}
