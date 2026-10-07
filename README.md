# Second Backend Service (GovApps Token Exchange)

Микросервис на Spring Boot (Java 25) для обмена OIDC ID-токенов, полученных от Keycloak / Alem Gateway, на собственные токены сервиса (Access и Refresh) с верификацией цифровой подписи через JWKS Alem backend.

---

## Архитектура и принцип работы

1. Пользователь проходит аутентификацию в системе (через Keycloak или BFF Gateway `alem`).
2. Клиентское приложение получает `id_token` (подписанный Keycloak RSA-ключом).
3. Клиент отправляет `id_token` в **Second Backend** (`POST /api/auth/exchange`).
4. **Second Backend** запрашивает и кэширует публичные ключи JWKS с эндпоинта `alem` (`http://localhost:8080/api/auth/jwks`).
5. **Second Backend** валидирует криптографическую подпись RS256, сроки действия (`exp`, `nbf`) и извлекает информацию о пользователе (`sub`, `username`, `email`, `roles`).
6. После успешной валидации **Second Backend** выпускает свою пару токенов:
   - **Access Token** (JWT, HS256, TTL: 15 минут) с `issuer: "second-backend"`, `audience: "second-service"`.
   - **Refresh Token** (JWT, HS256, TTL: 7 дней).
7. Клиент может обращаться к защищенным API Second Backend с полученным `Authorization: Bearer <second_access_token>`, а также обновлять токены через `POST /api/auth/refresh`.

---

## REST API Эндпоинты

### 1. Обмен ID-токена на токены Second
`POST /api/auth/exchange`

**Запрос:**
```json
{
  "id_token": "eyJhbGciOiJSUzI1NiIs..."
}
```

**Ответ (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_expires_in": 604800,
  "user": {
    "sub": "b2f67ac1-4321-...",
    "username": "aitu3",
    "email": "aitu3@example.com",
    "name": "Aitu User",
    "roles": ["user", "offline_access"]
  }
}
```

---

### 2. Обновление токенов по Refresh Token
`POST /api/auth/refresh`

**Запрос:**
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

**Ответ (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_expires_in": 604800,
  "user": {
    "sub": "b2f67ac1-4321-...",
    "username": "aitu3"
  }
}
```

---

### 3. Защищенный ресурс (Проверка авторизации)
`GET /api/second/me`

**Заголовок:**
```http
Authorization: Bearer <second_access_token>
```

**Ответ (200 OK):**
```json
{
  "success": true,
  "message": "Успешная авторизация в Second Backend",
  "data": {
    "service": "second-backend",
    "issuer": "second-backend",
    "audience": ["second-service"],
    "authorized_at": "2026-10-07T08:50:00Z",
    "user": {
      "sub": "b2f67ac1-4321-...",
      "username": "aitu3",
      "email": "aitu3@example.com",
      "roles": ["user"]
    }
  }
}
```

---

## Конфигурация (`application.yaml`)

```yaml
server:
  port: 8081

spring:
  application:
    name: second

alem:
  jwks-url: http://localhost:8080/api/auth/jwks

jwt:
  secret: second-backend-super-secret-key-that-is-at-least-256-bits-long-for-hmac-sha256
  issuer: second-backend
  audience: second-service
  access-token-expiration-seconds: 900       # 15 минут
  refresh-token-expiration-seconds: 604800   # 7 дней

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
