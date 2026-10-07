package com.example.second.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;

public record RefreshTokenRequest(
    @NotBlank(message = "refresh_token не может быть пустым")
    @JsonProperty("refresh_token")
    String refreshToken
) {}
