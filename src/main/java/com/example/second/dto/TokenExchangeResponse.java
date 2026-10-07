package com.example.second.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

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
