package com.example.second.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(description = "Общий формат ответа: успех или ошибка")
public record ApiResponse<T>(
    @Schema(example = "false") boolean success,
    @Schema(description = "Сообщение (при ошибке — причина и подсказка)", example = "Описание ошибки") String message,
    @Schema(description = "Данные ответа", nullable = true) T data
) {
    public static <T> ApiResponse<T> ok(String message, T data) {
        return new ApiResponse<>(true, message, data);
    }

    public static <T> ApiResponse<T> ok(String message) {
        return new ApiResponse<>(true, message, null);
    }

    public static <T> ApiResponse<T> error(String message) {
        return new ApiResponse<>(false, message, null);
    }
}
