package com.authserver.oidc.config;

import com.authserver.oidc.config.properties.AppSessionCookieProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;

/**
 * Configuration for HTTP session cookie attributes.
 * 
 * Registers a CookieSerializer bean to control session cookie behavior
 * (name, domain, path, HttpOnly, Secure, SameSite, maxAge).
 * 
 * Only active when Spring Session is present (via @ConditionalOnClass).
 * All configuration values come from application.yml via AppSessionCookieProperties.
 * 
 * IMPORTANT:
 * - Does NOT modify session storage (Redis remains unchanged)
 * - Does NOT alter Authorization Server or SAML login logic
 * - Only configures how the session cookie is emitted to the browser
 * 
 * Defaults:
 * - name: SESSION
 * - path: /
 * - httpOnly: true
 * - secure: true (prod), false (test)
 * - sameSite: Lax
 * - maxAge: not set (session cookie)
 * 
 * @see AppSessionCookieProperties
 */
@Configuration
@ConditionalOnClass(DefaultCookieSerializer.class)
public class SessionCookieConfig {
    
    private static final Logger logger = LoggerFactory.getLogger(SessionCookieConfig.class);
    
    private final AppSessionCookieProperties cookieProperties;
    
    public SessionCookieConfig(AppSessionCookieProperties cookieProperties) {
        this.cookieProperties = cookieProperties;
    }
    
    /**
     * Configure session cookie serializer with properties from application.yml.
     * 
     * Applies:
     * - Cookie name (if not null)
     * - Domain (only if not empty)
     * - Path
     * - HttpOnly flag
     * - Secure flag
     * - SameSite attribute
     * - MaxAge (only if not empty and remember-me is enabled)
     * 
     * @return CookieSerializer configured with properties
     */
    @Bean
    public CookieSerializer cookieSerializer() {
        logger.info("🍪 Configuring session cookie serializer from application.yml");
        
        DefaultCookieSerializer serializer = new DefaultCookieSerializer();
        
        // Cookie name
        if (cookieProperties.getName() != null && !cookieProperties.getName().isBlank()) {
            serializer.setCookieName(cookieProperties.getName());
            logger.info("   ├─ name: {}", cookieProperties.getName());
        }
        
        // Domain (only if explicitly set)
        if (cookieProperties.getDomain() != null && !cookieProperties.getDomain().isBlank()) {
            serializer.setDomainName(cookieProperties.getDomain());
            logger.info("   ├─ domain: {}", cookieProperties.getDomain());
        } else {
            logger.info("   ├─ domain: (not set, scoped to current domain)");
        }
        
        // Path
        serializer.setCookiePath(cookieProperties.getPath());
        logger.info("   ├─ path: {}", cookieProperties.getPath());
        
        // HttpOnly
        serializer.setUseHttpOnlyCookie(cookieProperties.isHttpOnly());
        logger.info("   ├─ httpOnly: {}", cookieProperties.isHttpOnly());
        
        // Secure
        serializer.setUseSecureCookie(cookieProperties.isSecure());
        logger.info("   ├─ secure: {}", cookieProperties.isSecure());
        
        // SameSite
        if (cookieProperties.getSameSite() != null && !cookieProperties.getSameSite().isBlank()) {
            serializer.setSameSite(cookieProperties.getSameSite());
            logger.info("   ├─ sameSite: {}", cookieProperties.getSameSite());
        }
        
        // MaxAge (only if explicitly set and remember-me is enabled)
        if (cookieProperties.getMaxAge() != null && !cookieProperties.getMaxAge().isBlank()) {
            try {
                int maxAgeSeconds = Integer.parseInt(cookieProperties.getMaxAge());
                
                if (cookieProperties.isRememberMe()) {
                    serializer.setCookieMaxAge(maxAgeSeconds);
                    logger.info("   ├─ maxAge: {} seconds (remember-me enabled)", maxAgeSeconds);
                } else {
                    logger.info("   ├─ maxAge: {} seconds configured but remember-me=false, using session cookie", maxAgeSeconds);
                }
            } catch (NumberFormatException e) {
                logger.warn("   ├─ maxAge: invalid value '{}', using default (session cookie)", cookieProperties.getMaxAge());
            }
        } else {
            logger.info("   └─ maxAge: (not set, session cookie expires when browser closes)");
        }
        
        logger.info("✅ Session cookie serializer configured successfully");
        
        return serializer;
    }
}
