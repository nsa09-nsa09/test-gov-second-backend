package com.example.second.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;

public record ExchangeAccessTokenRequest(
    @NotBlank(message = "access_token не может быть пустым")
    @JsonProperty("access_token")
    String accessToken
) {}
