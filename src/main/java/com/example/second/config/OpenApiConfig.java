package com.example.second.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenApiConfig {

    public static final String BEARER_SCHEME = "bearerAuth";

    @Bean
    public OpenAPI secondOpenApi(@Value("${server.port:8081}") int port,
                                 @Value("${keycloak.issuer:http://localhost:8180/realms/GovApps}") String issuer,
                                 @Value("${keycloak.client-id:second-backend}") String clientId) {
        String description = """
                Второй backend GovApps. Получает access token, выданный **alem** (клиент Keycloak `test-app`),
                и через **RFC 8693 Standard Token Exchange** в Keycloak выпускает собственный токен клиента `%2$s`.

                ### Поток
                ```
                1. Frontend → alem   POST /api/auth/login              → access_token A (azp=test-app, aud∋%2$s)
                2. Frontend → second POST /api/auth/token-exchange {A}
                3. second   → Keycloak grant_type=token-exchange, subject_token=A, client=%2$s
                4. Keycloak → second access_token B (azp=%2$s)
                5. Frontend → second GET /api/second/me  Bearer B → 200
                                     GET /api/second/me  Bearer A → 401
                ```

                ### Как проверить в Swagger
                1. Получите токен A в Swagger alem (`http://localhost:8080/swagger-ui.html`, `POST /api/auth/login`).
                2. Здесь: **Authorize** → вставьте A → `GET /api/second/token-info` (`accepted_by_me=false`) и `GET /api/second/me` (401).
                3. `POST /api/auth/token-exchange` (тело можно оставить пустым — токен возьмётся из Authorize).
                4. **Authorize** → вставьте `access_token` из ответа → `GET /api/second/me` (200).
                5. `POST /api/auth/token-exchange/introspect` для A и B — разные `client_id`/`azp`.

                ### Настройки Keycloak (realm из issuer `%1$s`)
                - Клиент `%2$s`: Client authentication = On, **Standard Token Exchange = On**.
                - Клиент `test-app`: Audience mapper, добавляющий `%2$s` в `aud` access token.
                - Опционально, для refresh_token после обмена: `%2$s` → Advanced → *Allow refresh token in Standard Token Exchange* = Same session.
                """.formatted(issuer, clientId);

        return new OpenAPI()
                .info(new Info()
                        .title("Second Backend API")
                        .version("1.0.0")
                        .description(description))
                .servers(List.of(new Server().url("http://localhost:" + port).description("Local")))
                .components(new Components().addSecuritySchemes(BEARER_SCHEME, new SecurityScheme()
                        .type(SecurityScheme.Type.HTTP)
                        .scheme("bearer")
                        .bearerFormat("JWT")
                        .description("Access token: токен alem для /token-exchange или токен second-backend для /api/second/me")));
    }
}
