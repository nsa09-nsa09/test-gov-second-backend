package com.example.second.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

@Schema(description = "Токен для проверки через Keycloak introspection")
public record IntrospectRequest(
    @Schema(description = "Любой access или refresh token realm GovApps", example = "eyJhbGciOiJSUzI1NiIs...")
    @NotBlank(message = "token не может быть пустым")
    String token
) {}
