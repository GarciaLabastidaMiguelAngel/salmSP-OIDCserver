package com.authserver.oidc.logout;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;

import java.time.Duration;
import java.util.UUID;

/**
 * Repository for managing logout contexts in Redis.
 * Used to maintain state during OIDC → SAML logout flow.
 * Only enabled when Redis is available.
 */
@Repository
@ConditionalOnProperty(name = "oidc.logout.enabled", havingValue = "true", matchIfMissing = true)
public class LogoutContextRepository {
    
    private static final String KEY_PREFIX = "logout:context:";
    private static final Duration TTL = Duration.ofSeconds(120); // 2 minutes
    
    private final RedisTemplate<String, Object> redisTemplate;
    
    public LogoutContextRepository(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }
    
    /**
     * Save logout context and return generated logout_state (RelayState).
     */
    public String save(OidcLogoutContext context) {
        String logoutState = UUID.randomUUID().toString();
        String key = KEY_PREFIX + logoutState;
        redisTemplate.opsForValue().set(key, context, TTL);
        return logoutState;
    }
    
    /**
     * Retrieve and DELETE logout context by logout_state.
     */
    public OidcLogoutContext findAndDelete(String logoutState) {
        if (logoutState == null || logoutState.isBlank()) {
            return null;
        }
        String key = KEY_PREFIX + logoutState;
        OidcLogoutContext context = (OidcLogoutContext) redisTemplate.opsForValue().get(key);
        if (context != null) {
            redisTemplate.delete(key);
        }
        return context;
    }
}
