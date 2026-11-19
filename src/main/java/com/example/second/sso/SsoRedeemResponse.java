package com.example.second.sso;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Данные пользователя для сервиса и его токен (aud = сервис)")
public record SsoRedeemResponse(
        @Schema(description = "sub пользователя в Keycloak") String userId,
        @Schema(description = "ФИО (claim name)") String fullName,
        @Schema(description = "Email") String email,
        @Schema(description = "Access token с aud = сервис, ~30 минут, без refresh") String accessToken
) {
}
