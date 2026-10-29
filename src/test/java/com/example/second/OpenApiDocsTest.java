package com.example.second;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.web.client.RestClient;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class OpenApiDocsTest {

    @Value("${local.server.port}")
    private int port;

    @Test
    @DisplayName("/v3/api-docs содержит все endpoints и bearerAuth, Swagger UI доступен")
    void apiDocsContainsEndpoints() throws Exception {
        RestClient client = RestClient.create("http://localhost:" + port);

        JsonNode docs = new ObjectMapper().readTree(client.get().uri("/v3/api-docs").retrieve().body(String.class));
        JsonNode paths = docs.path("paths");

        for (String path : new String[]{
                "/api/auth/token-exchange", "/api/auth/token-exchange/refresh", "/api/auth/token-exchange/introspect",
                "/api/second/me", "/api/second/token-info"}) {
            assertTrue(paths.has(path), "Нет пути в OpenAPI: " + path);
        }
        assertEquals(5, paths.size(), "Лишние пути в OpenAPI: " + paths.fieldNames().next());
        assertEquals("bearer", docs.path("components").path("securitySchemes").path("bearerAuth").path("scheme").asText());

        String ui = client.get().uri("/swagger-ui/index.html").retrieve().body(String.class);
        assertTrue(ui.contains("swagger-ui"));
    }
}
