package com.example.second.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Пара токенов (legacy-формат)")
public record TokenExchangeResponse(
    @JsonProperty("access_token")
    String accessToken,

    @JsonProperty("refresh_token")
    String refreshToken,

    @JsonProperty("token_type")
    String tokenType,

    @JsonProperty("expires_in")
    long expiresIn,

    @JsonProperty("refresh_expires_in")
    long refreshExpiresIn,

    UserInfoDto user
) {}
