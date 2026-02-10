package com.authserver.oidc.logout;

import java.io.Serializable;
import java.time.Instant;

/**
 * Context stored in Redis during OIDC → SAML logout flow.
 * Contains info needed to complete the logout after SAML callback.
 */
public class OidcLogoutContext implements Serializable {
    private static final long serialVersionUID = 1L;
    
    private String postLogoutRedirectUri;
    private String state; // OIDC state from client
    private String clientId;
    private Instant createdAt;
    
    public OidcLogoutContext() {
        this.createdAt = Instant.now();
    }
    
    public OidcLogoutContext(String postLogoutRedirectUri, String state, String clientId) {
        this.postLogoutRedirectUri = postLogoutRedirectUri;
        this.state = state;
        this.clientId = clientId;
        this.createdAt = Instant.now();
    }
    
    public String getPostLogoutRedirectUri() {
        return postLogoutRedirectUri;
    }
    
    public void setPostLogoutRedirectUri(String postLogoutRedirectUri) {
        this.postLogoutRedirectUri = postLogoutRedirectUri;
    }
    
    public String getState() {
        return state;
    }
    
    public void setState(String state) {
        this.state = state;
    }
    
    public String getClientId() {
        return clientId;
    }
    
    public void setClientId(String clientId) {
        this.clientId = clientId;
    }
    
    public Instant getCreatedAt() {
        return createdAt;
    }
    
    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }
    
    public boolean isExpired(int ttlSeconds) {
        return Instant.now().isAfter(createdAt.plusSeconds(ttlSeconds));
    }
}
