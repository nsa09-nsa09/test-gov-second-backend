package com.example.second.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;

import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(description = "Результат Keycloak Token Introspection (RFC 7662), выполненной от имени second-backend")
public record IntrospectionResponse(
    @Schema(description = "true, если токен валиден и не отозван", example = "true") boolean active,
    @JsonProperty("client_id") @Schema(example = "second-backend") String clientId,
    @Schema(example = "second-backend") String azp,
    @Schema(example = "[\"second-backend\"]") List<String> aud,
    @Schema(example = "b2f67ac1-4321-4b7c-9a1e-0c3f5d6e7a8b") String sub,
    @Schema(example = "aitu3") String username,
    @JsonProperty("token_type") @Schema(example = "Bearer") String tokenType,
    @Schema(example = "openid profile email") String scope,
    @Schema(example = "http://localhost:8180/realms/GovApps") String iss,
    @Schema(description = "ISO-8601", example = "2026-10-29T18:00:00Z") String iat,
    @Schema(description = "ISO-8601", example = "2026-10-29T18:05:00Z") String exp
) {}
