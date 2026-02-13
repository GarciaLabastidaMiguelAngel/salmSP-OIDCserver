package com.authserver.oidc.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Configuration properties for HTTP session cookie.
 * 
 * Controls cookie attributes: name, domain, path, HttpOnly, Secure, SameSite, maxAge.
 * All values are externalized to application.yml (no hardcoded values).
 * 
 * Usage in application.yml:
 * <pre>
 * app:
 *   session:
 *     cookie:
 *       name: SESSION
 *       domain: ""
 *       path: /
 *       http-only: true
 *       secure: true
 *       same-site: Lax
 *       max-age: ""
 *       remember-me: false
 * </pre>
 * 
 * @see SessionCookieConfig
 */
@Component
@ConfigurationProperties(prefix = "app.session.cookie")
public class AppSessionCookieProperties {
    
    /**
     * Cookie name (e.g., SESSION, JSESSIONID).
     * Default: SESSION
     */
    private String name = "SESSION";
    
    /**
     * Cookie domain attribute.
     * Empty string = not set (cookie is scoped to current domain).
     * Example: ".example.com" for subdomain sharing.
     * Default: empty (not set)
     */
    private String domain = "";
    
    /**
     * Cookie path attribute.
     * Default: /
     */
    private String path = "/";
    
    /**
     * HttpOnly flag (prevents JavaScript access).
     * Default: true
     */
    private boolean httpOnly = true;
    
    /**
     * Secure flag (requires HTTPS).
     * Default: true (production), false (test profile)
     */
    private boolean secure = true;
    
    /**
     * SameSite attribute (Lax, Strict, None).
     * - Lax: Allows cross-site top-level navigation (recommended for most cases)
     * - Strict: No cross-site requests
     * - None: Allows all cross-site requests (requires Secure=true)
     * Default: Lax
     */
    private String sameSite = "Lax";
    
    /**
     * Cookie max-age in seconds.
     * Empty string = not set (session cookie, expires when browser closes).
     * Positive value = persistent cookie.
     * Default: empty (session cookie)
     */
    private String maxAge = "";
    
    /**
     * Enable remember-me behavior.
     * If true and maxAge is set, cookie persists across browser restarts.
     * Default: false
     */
    private boolean rememberMe = false;
    
    // Getters and setters
    
    public String getName() {
        return name;
    }
    
    public void setName(String name) {
        this.name = name;
    }
    
    public String getDomain() {
        return domain;
    }
    
    public void setDomain(String domain) {
        this.domain = domain;
    }
    
    public String getPath() {
        return path;
    }
    
    public void setPath(String path) {
        this.path = path;
    }
    
    public boolean isHttpOnly() {
        return httpOnly;
    }
    
    public void setHttpOnly(boolean httpOnly) {
        this.httpOnly = httpOnly;
    }
    
    public boolean isSecure() {
        return secure;
    }
    
    public void setSecure(boolean secure) {
        this.secure = secure;
    }
    
    public String getSameSite() {
        return sameSite;
    }
    
    public void setSameSite(String sameSite) {
        this.sameSite = sameSite;
    }
    
    public String getMaxAge() {
        return maxAge;
    }
    
    public void setMaxAge(String maxAge) {
        this.maxAge = maxAge;
    }
    
    public boolean isRememberMe() {
        return rememberMe;
    }
    
    public void setRememberMe(boolean rememberMe) {
        this.rememberMe = rememberMe;
    }
}
