package com.authserver.oidc.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;

/**
 * Spring Session with Redis configuration.
 * 
 * This configuration enables distributed session storage using Redis,
 * allowing for horizontal scalability and session persistence across
 * multiple instances of the authorization server.
 * 
 * Features:
 * - Distributed session storage in Redis
 * - Session timeout of 30 minutes (1800 seconds)
 * - Automatic session replication
 * - Spring Security integration (automatically manages JSESSIONID)
 * 
 * Redis connection is auto-configured from application.yml:
 * - spring.redis.host (default: localhost)
 * - spring.redis.port (default: 6379)
 * - spring.redis.password (if required)
 * 
 * NOTE: OAuth2AuthorizationService uses H2/JDBC, NOT Redis.
 * Only HTTP sessions are stored in Redis.
 */
@Configuration
@EnableRedisHttpSession(maxInactiveIntervalInSeconds = 1800)
public class SessionConfig {
    
    /**
     * RedisTemplate for general-purpose Redis operations (logout context, etc.)
     */
    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(new GenericJackson2JsonRedisSerializer());
        template.setHashKeySerializer(new StringRedisSerializer());
        template.setHashValueSerializer(new GenericJackson2JsonRedisSerializer());
        return template;
    }

}
