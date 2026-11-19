package com.example.second.sso;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Токен пользователя для сервиса (aud = сервис). Данные пользователя сервис берёт из его claims: sub, name, email")
public record SsoRedeemResponse(
        @Schema(description = "Access token с aud = сервис, без refresh") String accessToken
) {
}
