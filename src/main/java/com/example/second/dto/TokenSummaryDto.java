package com.example.second.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;

import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(description = "Ключевые claims JWT (без подписи), чтобы сравнить токены до и после обмена")
public record TokenSummaryDto(
    @Schema(example = "http://localhost:8180/realms/GovApps") String iss,
    @Schema(description = "Authorized party: клиент, которому выдан токен", example = "second-backend") String azp,
    @Schema(example = "[\"second-backend\"]") List<String> aud,
    @Schema(example = "b2f67ac1-4321-4b7c-9a1e-0c3f5d6e7a8b") String sub,
    @JsonProperty("preferred_username") @Schema(example = "aitu3") String preferredUsername,
    @Schema(example = "onrtac:5c0e3f2a-...") String jti,
    @Schema(example = "Bearer") String typ,
    @Schema(example = "openid profile email") String scope,
    @Schema(description = "Время выпуска (ISO-8601)", example = "2026-10-29T18:00:00Z") String iat,
    @Schema(description = "Время истечения (ISO-8601)", example = "2026-10-29T18:05:00Z") String exp
) {}
