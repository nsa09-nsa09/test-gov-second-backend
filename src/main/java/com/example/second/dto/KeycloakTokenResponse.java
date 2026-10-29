package com.example.second.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(description = "Токены second-backend, выпущенные Keycloak")
public record KeycloakTokenResponse(
    @JsonProperty("access_token")
    @Schema(description = "Новый access token (RS256, azp=second-backend)", example = "eyJhbGciOiJSUzI1NiIs...")
    String accessToken,

    @JsonProperty("refresh_token")
    @Schema(description = "Refresh token Keycloak. Отсутствует, если Keycloak его не выдал", example = "eyJhbGciOiJIUzUxMiIs...", nullable = true)
    String refreshToken,

    @JsonProperty("token_type")
    @Schema(example = "Bearer")
    String tokenType,

    @JsonProperty("expires_in")
    @Schema(description = "Время жизни access token, сек", example = "300")
    long expiresIn,

    @JsonProperty("refresh_expires_in")
    @Schema(description = "Время жизни refresh token, сек (0, если refresh token нет)", example = "1800")
    long refreshExpiresIn,

    @JsonProperty("issued_token_type")
    @Schema(description = "RFC 8693: тип выпущенного токена", example = "urn:ietf:params:oauth:token-type:access_token", nullable = true)
    String issuedTokenType,

    @Schema(example = "openid profile email", nullable = true)
    String scope,

    UserInfoDto user,

    @Schema(description = "Claims до/после обмена. Только в ответе /token-exchange", nullable = true)
    ExchangeDetailsDto exchange,

    @Schema(description = "Подсказка по настройке Keycloak, если что-то не выдано", nullable = true,
            example = "Keycloak не выдал refresh_token: ...")
    String hint
) {}
