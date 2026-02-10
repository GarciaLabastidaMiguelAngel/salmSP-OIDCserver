# OIDC Authorization Server

✅ **Estado**: Consolidado y homologado - Sin duplicidades  
📅 **Última actualización**: 2026-02-09

OpenID Connect Authorization Server con soporte SAML2 Service Provider, Redis Session y debug completo.

## Features

- **OIDC/OAuth2**: Full Authorization Server (Spring Authorization Server 1.3.2)
  - Authorization Code flow + PKCE
  - Refresh Token support
  - ID Token con claims completos (sid, azp, nonce, roles, acr, amr, auth_time)
  - UserInfo endpoint con atributos SAML
- **SAML2 SP**: Service Provider con autenticación contra IdP SAML externo
  - POST Binding con firma de AuthnRequest
  - Debug completo de AuthnRequest XML (dev/preprod only)
- **Redis Session**: Spring Session Data Redis (30 min timeout)
- **H2 Database**: In-memory JDBC storage para OAuth2 (clients, authorizations, consents)
- **Multi-Profile**: dev (SAML debug), preprod, prod (SAML debug bloqueado)

## Requirements

- **Java**: 17+
- **Maven**: 3.9+
- **Redis**: 6.x+ (para sessions)

## Stack

- Spring Boot 3.4.1
- Spring Authorization Server 1.3.2
- Spring Security 6.4.x
- Spring Session Data Redis
- H2 Database (in-memory)

## Quick Start

### 1. Build

```bash
cd /Users/miguel/Documents/FIFO/oauthserver-oidc-server
mvn clean package -DskipTests
```

### 2. Run (Development)

```bash
# Maven (recomendado para desarrollo)
mvn spring-boot:run -Dspring-boot.run.profiles=dev

# JAR directo
java -Dspring.profiles.active=dev -jar target/oidc-auth-server-1.0.0.jar

# Background
java -Dspring.profiles.active=dev -jar target/oidc-auth-server-1.0.0.jar &
```

**Profile activo**: `dev`  
**Puerto**: 8080  
**SAML**: ✅ Habilitado  
**SAML Debug**: ✅ Habilitado (logs XML completo sin truncar)

### 3. Validar Endpoints

```bash
# OIDC Discovery
curl -s http://localhost:8080/.well-known/openid-configuration | python3 -m json.tool

# JWKS
curl -s http://localhost:8080/oauth2/jwks | python3 -m json.tool

# Authorization Endpoint (redirect a SAML)
curl -v "http://localhost:8080/oauth2/authorize?response_type=code&client_id=fifo-client&redirect_uri=http://localhost:8081/callback&scope=openid"
```

**Esperado**:
- Discovery: HTTP 200, JSON con `issuer`, `authorization_endpoint`, `token_endpoint`, etc.
- JWKS: HTTP 200, JSON con array `keys[]` con `kty=RSA`
- Authorize: HTTP 302 redirect a `/saml2/authenticate/bet`
curl -i "http://localhost:8080/saml2/authenticate/bet"
# Expected: HTTP/1.1 302 with Location header containing SAMLRequest
```

## Configuration

All configuration in `src/main/resources/application.yml`:

### OIDC Settings
- **Issuer**: `http://localhost:8080` (change for production)
- **Keystore**: `keystore/oidc-keystore.p12` (auto-generated, RSA 2048)

### SAML Settings
- **Registration ID**: `bet`
- **SP Entity ID**: `{baseUrl}/saml2/service-provider-metadata/bet`
- **ACS URL**: `{baseUrl}/login/saml2/sso/bet`
- **IdP**: Configure in `saml.idp.*` properties

### Default OAuth2 Clients
- **Client ID**: `fifo-client`
- **Client Secret**: `secret`
- **Redirect URIs**: `http://localhost:8081/login/oauth2/code/fifo`, `http://127.0.0.1:8081/login/oauth2/code/fifo`, `http://localhost:8081/callback`
- **Scopes**: `openid`, `profile`, `email`
- **Grant Types**: `authorization_code`, `refresh_token`

Additional local/manual client:
- **Client ID**: `example-client`
- **Client Secret**: `example-secret`
- **Redirect URIs**: `http://localhost:8081/callback`
- **Scopes**: `openid`, `profile`, `email`
- **Grant Types**: `authorization_code`, `refresh_token`

## Endpoints

### OIDC (Spring Authorization Server)
- `GET /.well-known/openid-configuration` - Discovery
- `GET /oauth2/jwks` - JSON Web Key Set
- `GET /oauth2/authorize` - Authorization endpoint (requires authentication)
- `POST /oauth2/token` - Token endpoint
- `GET /userinfo` - UserInfo endpoint (if configured)

### SAML2 (Spring Security SAML)
- `GET /saml2/authenticate/bet` - Initiate SAML authentication (302 to IdP)
- `POST /login/saml2/sso/bet` - Assertion Consumer Service (ACS)
- `GET /saml2/service-provider-metadata/bet` - SP metadata

## Architecture

```
┌─────────────────────────────────────────────┐
│   Spring Authorization Server (Order 1)     │
│   - OIDC Discovery                          │
│   - OAuth2 /authorize, /token, /jwks       │
│   - JWT signing with RSA keystore          │
└─────────────────────────────────────────────┘
                    ▲
                    │
┌─────────────────────────────────────────────┐
│   Spring Security SAML2 SP (Order 2)        │
│   - /saml2/authenticate/bet → IdP          │
│   - POST /login/saml2/sso/bet (ACS)        │
│   - Standard RelayState handling           │
└─────────────────────────────────────────────┘
                    ▲
                    │
            External SAML IdP
```

## Storage

- **OAuth2 Clients**: JDBC (H2 in-memory) via `oauth2_registered_client`
- **Authorizations**: JDBC (H2 in-memory) via `oauth2_authorization`
- **Sessions**: In-memory (no Redis in minimal setup)

## Development

### Generate New Keystores

```bash
# OIDC keystore
keytool -genkeypair -alias oidc -keyalg RSA -keysize 2048 \
  -storetype PKCS12 -keystore src/main/resources/keystore/oidc-keystore.p12 \
  -storepass changeit -keypass changeit -validity 3650 \
  -dname "CN=OIDC Server, OU=Dev, O=Example, L=City, ST=State, C=US"

# SAML keystore with SP and mock IdP certs
keytool -genkeypair -alias saml -keyalg RSA -keysize 2048 \
  -storetype PKCS12 -keystore src/main/resources/keystore/saml-keystore.p12 \
  -storepass changeit -keypass changeit -validity 3650 \
  -dname "CN=SAML SP, OU=Dev, O=Example, L=City, ST=State, C=US"

keytool -genkeypair -alias idp -keyalg RSA -keysize 2048 \
  -storetype PKCS12 -keystore src/main/resources/keystore/saml-keystore.p12 \
  -storepass changeit -keypass changeit -validity 3650 \
  -dname "CN=SAML IdP Mock, OU=Dev, O=Example, L=City, ST=State, C=US"
```

### Logs

Set log level in `application.yml`:

```yaml
logging:
  level:
    org.springframework.security: DEBUG
    org.springframework.security.saml2: DEBUG
```

## 400 Bad Request (Authorize) Checklist

- **Repro URL**: `http://localhost:8080/oauth2/authorize?response_type=code&client_id=example-client&redirect_uri=http://localhost:8081/callback&scope=openid%20profile%20email&state=test-state-123&nonce=test-nonce-456&code_challenge=YXL3LdJD3VuFil0hIpXgDLLP5YrpRq50TCqFqP1anuc&code_challenge_method=S256`
- **Log Message**: `Authorization request failed: [invalid_request] OAuth 2.0 Parameter: client_id`
- **Fix Applied**: registered `example-client` in `OidcAuthorizationServerConfig` with `http://localhost:8081/callback`
- **Expected Output**: `302` to `/saml2/authenticate/bet` when unauthenticated, or `302` to `redirect_uri` with `code` and `state` when authenticated

## Next Steps (Future Enhancements)

This is the **minimal baseline**. Add later:

1. **Session-Claims**: Map SAML attributes to OIDC claims
2. **ACR/AMR**: Authentication Context Class/Method Reference
3. **Redis Sessions**: Distributed session storage
4. **Replay Protection**: SAML message ID validation
5. **Consent Screen**: OAuth2 authorization consent
6. **Custom Login**: Branded login pages
7. **Multi-IdP**: Support multiple SAML identity providers
8. **Tests**: Integration tests for full flow

## License

Example code for educational purposes.
