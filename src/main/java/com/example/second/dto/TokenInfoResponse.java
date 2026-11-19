package com.example.second.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;

import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(description = "Отладочный отчёт: примет ли GET /api/second/me этот токен и почему")
public record TokenInfoResponse(
    @Schema(description = "Алгоритм подписи из заголовка JWT", example = "RS256") String alg,
    @Schema(description = "Идентификатор ключа из заголовка JWT", example = "Xx9kQ...") String kid,
    TokenSummaryDto claims,
    List<TokenCheckDto> checks,
    @JsonProperty("accepted_by_me")
    @Schema(description = "Итог: пропустит ли /api/second/me этот токен", example = "true") boolean acceptedByMe
) {}
