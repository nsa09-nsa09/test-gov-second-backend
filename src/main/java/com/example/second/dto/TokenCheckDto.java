package com.example.second.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Результат одной проверки токена")
public record TokenCheckDto(
    @Schema(description = "Название проверки", example = "authorized_party") String name,
    @Schema(example = "false") boolean passed,
    @Schema(example = "azp='test-app', ожидается 'second-backend'") String detail
) {
    public static TokenCheckDto ok(String name, String detail) {
        return new TokenCheckDto(name, true, detail);
    }

    public static TokenCheckDto fail(String name, String detail) {
        return new TokenCheckDto(name, false, detail);
    }
}
