# Redis OAuth2 Authorization Service - Integration Tests

## Overview

This directory contains integration tests for `RedisOAuth2AuthorizationService`, validating the complete OAuth2 Authorization Code flow with Redis storage, atomic Lua operations, and client binding validation.

## Test Coverage

The test suite (`RedisOAuth2AuthorizationServiceIT`) validates:

1. **SAVE creates state and TTLs** - Verifies auth, code index, and code binding creation with correct TTLs
2. **Code consumption (atomicity)** - Validates single-use authorization code consumption with binding validation
3. **Replay attack prevention** - Ensures consumed codes cannot be reused
4. **Client binding validation** - Prevents stolen codes from being used with wrong client_id
5. **Redirect URI binding validation** - Prevents stolen codes from being used with wrong redirect_uri
6. **Null tokenType handling** - Tests Spring Authorization Server's null tokenType fallback behavior
7. **Access token lookup** - Validates non-consuming token lookups
8. **Refresh token support** - Tests refresh token storage and lookup (feature flag controlled)
9. **Atomic removal** - Verifies all keys are deleted atomically
10. **Token hashing** - Confirms raw tokens never appear in Redis keys

## Technology Stack

- **JUnit 5** - Test framework
- **Testcontainers** - Real Redis container for integration tests (Docker required)
- **AssertJ** - Fluent assertions
- **Spring Mock** - MockHttpServletRequest for request context simulation

## Prerequisites

### Required

- **Java 17+**
- **Maven 3.8+**
- **Docker** - Required for Testcontainers to run Redis container
- **Docker daemon running** - Testcontainers will automatically pull `redis:7-alpine` image

### Optional

- **Docker Desktop** (macOS/Windows) or Docker Engine (Linux)

## Running Tests

### Run all tests

```bash
mvn test
```

### Run only Redis integration tests

```bash
mvn test -Dtest=RedisOAuth2AuthorizationServiceIT
```

### Run specific test

```bash
mvn test -Dtest=RedisOAuth2AuthorizationServiceIT#testSaveCreatesStateAndTTLs
```

### Skip tests (if Docker unavailable)

```bash
mvn package -DskipTests
```

## Test Utilities

### `OAuth2AuthorizationTestBuilder`

Builder for creating realistic OAuth2Authorization instances:

```java
OAuth2Authorization auth = OAuth2AuthorizationTestBuilder.builder()
    .registeredClientId("test-client")
    .principalName("test-user")
    .redirectUri("http://localhost:8080/callback")
    .authorizationCode("test-code-123")
    .accessToken("test-access-456")
    .refreshToken("test-refresh-789") // Optional
    .build();
```

**Convenience methods:**
- `buildWithCodeAndAccessToken()` - Typical OAuth2 flow
- `buildWithAllTokens()` - With refresh token support

### `RequestContextTestUtil`

Utility for simulating HTTP request context in tests:

```java
// Setup request with client_id and redirect_uri
RequestContextTestUtil.setupRequestContext("test-client", "http://localhost:8080/callback");

// Setup with HTTP Basic authentication
RequestContextTestUtil.setupRequestContextWithBasicAuth("test-client", "secret", "http://localhost:8080/callback");

// Cleanup after test
RequestContextTestUtil.clearRequestContext();
```

## Test Isolation

Each test:
- Runs in isolated Redis namespace (`test-as`)
- Cleans up all keys after execution (`@AfterEach`)
- Resets RequestContextHolder to prevent context leakage

## Troubleshooting

### Docker not running

```
Error: Could not find a valid Docker environment
```

**Solution:** Start Docker Desktop or Docker daemon before running tests.

### Port conflicts

```
Error: Bind for 0.0.0.0:6379 failed: port is already allocated
```

**Solution:** Testcontainers uses random ports, but if issue persists:
1. Stop local Redis: `brew services stop redis` (macOS)
2. Rerun tests

### Tests fail with "Connection refused"

**Solution:** Increase Docker resource limits:
- Docker Desktop → Settings → Resources → Memory: 4GB+

### Slow test execution

**First run:** Testcontainers downloads Redis image (~30 MB), subsequent runs are fast.

## Feature Flags

### Refresh Token Support

Refresh token support is **disabled by default** (`oidc.refresh-token.enabled=false`).

**Enable in tests:**
```java
oidcProperties.setRefreshTokenEnabled(true);
```

**Enable in production (future):**
```yaml
oidc:
  refresh-token:
    enabled: true
```

## Redis Key Structure

All keys use namespace prefix (`test-as` in tests, `as` in production):

| Key Pattern | Purpose | TTL |
|-------------|---------|-----|
| `as:auth:{authId}` | OAuth2Authorization JSON | Max TTL (access token expiry) |
| `as:token:code:{hash}` | Code index → authId | Code TTL (60s default) |
| `as:codebind:{hash}` | Code binding (clientId\|redirectUri) | Code TTL (60s default) |
| `as:token:access:{hash}` | Access token index → authId | Max TTL |
| `as:token:refresh:{hash}` | Refresh token index → authId | Max TTL |

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Integration Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-java@v3
        with:
          java-version: '17'
      - name: Run tests
        run: mvn test
```

Testcontainers automatically detects CI environments and adjusts configuration.

## Performance

- **Average test duration:** 10-15s (including Redis container startup)
- **Subsequent runs:** 5-7s (container reuse)
- **Total suite:** ~1 minute

## Next Steps

- [ ] Add tests for token revocation
- [ ] Add tests for concurrent code consumption (race conditions)
- [ ] Add performance benchmarks (throughput, latency)
- [ ] Add tests for Redis connection failures (resilience)

## References

- [Spring Authorization Server](https://docs.spring.io/spring-authorization-server/reference/)
- [Testcontainers](https://testcontainers.com/)
- [Redis Lua Scripting](https://redis.io/docs/manual/programmability/eval-intro/)
