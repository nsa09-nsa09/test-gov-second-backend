package com.example.second.dto;

import java.util.List;

public record UserInfoDto(
    String sub,
    String username,
    String email,
    String name,
    List<String> roles
) {}
