package com.example.second.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Сравнение исходного (subject) и выпущенного Keycloak токена")
public record ExchangeDetailsDto(
    @Schema(description = "Claims входного токена от alem (azp=test-app)") TokenSummaryDto subject,
    @Schema(description = "Claims нового токена second-backend (azp=second-backend)") TokenSummaryDto issued
) {}
