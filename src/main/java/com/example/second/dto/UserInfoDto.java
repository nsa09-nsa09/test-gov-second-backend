package com.example.second.dto;

import io.swagger.v3.oas.annotations.media.Schema;

import java.util.List;

@Schema(description = "Пользователь из claims токена")
public record UserInfoDto(
    @Schema(example = "b2f67ac1-4321-4b7c-9a1e-0c3f5d6e7a8b") String sub,
    @Schema(example = "aitu3") String username,
    @Schema(example = "aitu3@example.com") String email,
    @Schema(example = "Aitu User") String name,
    @Schema(example = "[\"user\", \"offline_access\"]") List<String> roles
) {}
