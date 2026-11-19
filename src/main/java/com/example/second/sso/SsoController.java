package com.example.second.sso;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/sso")
@Tag(name = "SSO", description = "Бесшовный вход в сервисы через одноразовый код")
public class SsoController {

    private final SsoService ssoService;

    public SsoController(SsoService ssoService) {
        this.ssoService = ssoService;
    }

    @Operation(summary = "Выдать одноразовый код для входа в сервис",
            description = "Authorization: Bearer <токен Alem>. Ответ: адрес callback сервиса с кодом.")
    @PostMapping("/{service}/start")
    public Map<String, String> start(@PathVariable("service") String service,
                                     @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        return Map.of("url", ssoService.start(service, bearer(authorization)));
    }

    @Operation(summary = "Обменять код на данные пользователя",
            description = "Вызывает бэкенд сервиса. Authorization: Bearer <секрет сервиса>, тело {\"code\": \"...\"}.")
    @PostMapping("/redeem")
    public SsoRedeemResponse redeem(@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
                                    @RequestBody Map<String, String> body) {
        return ssoService.redeem(bearer(authorization), body.get("code"));
    }

    private static String bearer(String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            return null;
        }
        return authorization.substring("Bearer ".length()).trim();
    }
}
