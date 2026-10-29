# Second Backend Service (GovApps Token Exchange)

Микросервис на Spring Boot (Java 25). Получает access token, выданный **alem** (клиент Keycloak `test-app`),
и через **RFC 8693 Standard Token Exchange** в Keycloak получает собственный токен клиента `second-backend`.

Swagger UI: http://localhost:8081/swagger-ui.html · OpenAPI: http://localhost:8081/v3/api-docs
(Swagger alem: http://localhost:8080/swagger-ui.html)

---

## Поток Token Exchange

```
1. Frontend → alem   POST /api/auth/login              → access_token A (azp=test-app, aud∋second-backend)
2. Frontend → second POST /api/auth/token-exchange {A}
3. second   → Keycloak grant_type=token-exchange, subject_token=A, client=second-backend (+secret)
4. Keycloak → second access_token B (azp=second-backend)
5. Frontend → second GET /api/second/me  Bearer B → 200
                     GET /api/second/me  Bearer A → 401 (токен выдан не для second-backend)
```

Перед запросом в Keycloak second проверяет subject_token локально: подпись RS256 по JWKS Keycloak
(`/realms/GovApps/protocol/openid-connect/certs`), `iss`, `exp` и наличие `second-backend` в `aud`.

### Настройки Keycloak (realm GovApps)
- Клиент `second-backend`: Client authentication = On, **Standard Token Exchange = On**.
- Клиент `test-app`: Audience mapper, добавляющий `second-backend` в `aud` access token.
- Опционально (refresh_token после обмена): `second-backend` → Advanced →
  *Allow refresh token in Standard Token Exchange* = Same session, и в запросе `requested_token_type=refresh_token`.

---

## REST API

| Метод | Путь | Описание |
|---|---|---|
| POST | `/api/auth/token-exchange` | RFC 8693 обмен токена alem на токен second-backend |
| POST | `/api/auth/token-exchange/refresh` | Обновление токена second-backend по refresh_token Keycloak |
| POST | `/api/auth/token-exchange/introspect` | Keycloak introspection от имени second-backend |
| GET | `/api/second/me` | Защищённый ресурс: только токены с `azp=second-backend` |
| GET | `/api/second/token-info` | Отладка: примет ли `/me` токен и какие проверки не прошли |

### `POST /api/auth/token-exchange`

`subject_token` — в теле или в заголовке `Authorization: Bearer`.

```json
{
  "subject_token": "eyJhbGciOiJSUzI1NiIs...",
  "scope": "openid profile",
  "requested_token_type": "access_token"
}
```

Ответ `200`:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 300,
  "refresh_expires_in": 0,
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "user": { "sub": "b2f67ac1-...", "username": "aitu3", "roles": ["user"] },
  "exchange": {
    "subject": { "azp": "test-app",       "aud": ["second-backend", "account"], "...": "..." },
    "issued":  { "azp": "second-backend", "aud": ["account"],                   "...": "..." }
  },
  "hint": "Keycloak не выдал refresh_token. ..."
}
```

Ошибки (`{"success": false, "message": "..."}`):

| Код | Причина |
|---|---|
| 400 | Нет subject_token; Keycloak вернул `invalid_request` / `invalid_token` / `invalid_grant` |
| 401 | subject_token не прошёл проверку (подпись, iss, exp); `invalid_client` (неверный secret) |
| 403 | В `aud` нет `second-backend`; Keycloak вернул `access_denied` / `unauthorized_client` (Standard Token Exchange выключен) |
| 502 | Keycloak вернул 5xx или некорректный ответ |
| 503 | Keycloak недоступен |

### Проверка вручную (curl)

```bash
# 1. Токен alem
A=$(curl -s -X POST http://localhost:8080/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"<user>","password":"<password>"}' | jq -r .access_token)

# 2. Токен alem в /me отклоняется (401), token-info показывает почему
curl -s http://localhost:8081/api/second/me -H "Authorization: Bearer $A" | jq
curl -s http://localhost:8081/api/second/token-info -H "Authorization: Bearer $A" | jq

# 3. Обмен
B=$(curl -s -X POST http://localhost:8081/api/auth/token-exchange -H 'Content-Type: application/json' \
  -d "{\"subject_token\":\"$A\"}" | tee /dev/stderr | jq -r .access_token)

# 4. Обменянный токен принимается (200)
curl -s http://localhost:8081/api/second/me -H "Authorization: Bearer $B" | jq

# 5. Introspection: client_id/azp у A — test-app, у B — second-backend
curl -s -X POST http://localhost:8081/api/auth/token-exchange/introspect -H 'Content-Type: application/json' -d "{\"token\":\"$B\"}" | jq
```

---

## Конфигурация (`application.yaml`)

```yaml
server:
  port: 8081

spring:
  application:
    name: second

keycloak:
  server-url: http://localhost:8180
  realm: GovApps
  client-id: second-backend
  client-secret: <secret из Clients → second-backend → Credentials>
  issuer: ${keycloak.server-url}/realms/${keycloak.realm}
  jwks-url: ${keycloak.server-url}/realms/${keycloak.realm}/protocol/openid-connect/certs

cors:
  allowed-origins:
    - http://localhost:5173
```

---

## Запуск и сборка

### Требования
- Java 25 (OpenJDK)
- Maven 3.9+ (или использовать `./mvnw`)

### Запуск тестов
```bash
./mvnw clean test
```

### Запуск приложения
```bash
./mvnw spring-boot:run
```
Сервис запустится на порту `8081`.

### Запуск в Docker
```bash
docker build -t govapps-second:local .
docker run --rm -p 8081:8081 -e LOCAL_FORWARD=8180:host.docker.internal:8180 govapps-second:local
```
`LOCAL_FORWARD` пробрасывает `127.0.0.1:8180` внутри контейнера на Keycloak хоста, чтобы сервис обращался к Keycloak
по `http://localhost:8180`, как и браузер: тогда issuer токенов совпадает у всех участников обмена.
