package com.example.second.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;

public record ExchangeTokenRequest(
    @NotBlank(message = "id_token не может быть пустым")
    @JsonProperty("id_token")
    String idToken
) {}
