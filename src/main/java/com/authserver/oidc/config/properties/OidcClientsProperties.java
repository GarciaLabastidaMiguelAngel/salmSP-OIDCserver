package com.authserver.oidc.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Configuration properties for OIDC Authorization Server.
 * Defines issuer and list of OAuth2 clients.
 * Clients are loaded from properties, NOT from database.
 */
@Component
@ConfigurationProperties(prefix = "oidc")
public class OidcClientsProperties {

    /**
     * OIDC Issuer URI (e.g., https://login.example.com).
     * Returned in /.well-known/openid-configuration.
     */
    @NotBlank(message = "oidc.issuer is required")
    private String issuer;

    /**
     * List of OAuth2 clients (registered from properties).
     */
    @Valid
    @NotEmpty(message = "oidc.clients cannot be empty; define at least one client")
    private List<ClientProperties> clients = new ArrayList<>();

    // Getters/Setters
    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public List<ClientProperties> getClients() {
        return clients;
    }

    public void setClients(List<ClientProperties> clients) {
        this.clients = clients;
    }

    /**
     * Nested class for individual client configuration.
     */
    public static class ClientProperties {

        /**
         * Client ID (OAuth2 client_id).
         */
        @NotBlank(message = "clientId is required")
        private String clientId;

        /**
         * Client secret (OAuth2 client_secret).
         * Can be plain text (will be wrapped with {noop}) or pre-encoded with {bcrypt}, {argon2}, etc.
         */
        @NotBlank(message = "clientSecret is required")
        private String clientSecret;

        /**
         * Client name for UI/logs.
         */
        private String clientName;

        /**
         * Client authentication methods: "client_secret_basic", "client_secret_post", "private_key_jwt", etc.
         */
        private Set<String> clientAuthMethods = Set.of("client_secret_basic", "client_secret_post");

        /**
         * Authorization grant types: "authorization_code", "refresh_token", "client_credentials", etc.
         */
        private Set<String> grantTypes = Set.of("authorization_code", "refresh_token");

        /**
         * Redirect URIs (for authorization_code flow).
         */
        private Set<String> redirectUris = new HashSet<>();

        /**
         * Post-logout redirect URIs (for OIDC logout endpoint).
         */
        private Set<String> postLogoutRedirectUris = new HashSet<>();

        /**
         * OAuth2 scopes (e.g., "openid", "profile", "email").
         */
        private Set<String> scopes = Set.of("openid", "profile", "email");

        /**
         * Require PKCE (RFC 7636).
         */
        private boolean requirePkce = false;

        /**
         * Access token format: "jwt" (self-contained) or "reference" (opaque).
         */
        private String accessTokenFormat = "jwt";

        /**
         * Access token TTL (ISO 8601 duration, e.g., "PT1H" = 1 hour).
         */
        private String accessTokenTtl = "PT1H";

        /**
         * Refresh token TTL (ISO 8601 duration, e.g., "P7D" = 7 days).
         */
        private String refreshTokenTtl = "P7D";

        /**
         * Reuse refresh tokens (true) or issue new ones (false).
         */
        private boolean reuseRefreshTokens = true;

        // Getters/Setters
        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getClientSecret() {
            return clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }

        public String getClientName() {
            return clientName;
        }

        public void setClientName(String clientName) {
            this.clientName = clientName;
        }

        public Set<String> getClientAuthMethods() {
            return clientAuthMethods;
        }

        public void setClientAuthMethods(Set<String> clientAuthMethods) {
            this.clientAuthMethods = clientAuthMethods;
        }

        public Set<String> getGrantTypes() {
            return grantTypes;
        }

        public void setGrantTypes(Set<String> grantTypes) {
            this.grantTypes = grantTypes;
        }

        public Set<String> getRedirectUris() {
            return redirectUris;
        }

        public void setRedirectUris(Set<String> redirectUris) {
            this.redirectUris = redirectUris;
        }

        public Set<String> getPostLogoutRedirectUris() {
            return postLogoutRedirectUris;
        }

        public void setPostLogoutRedirectUris(Set<String> postLogoutRedirectUris) {
            this.postLogoutRedirectUris = postLogoutRedirectUris;
        }

        public Set<String> getScopes() {
            return scopes;
        }

        public void setScopes(Set<String> scopes) {
            this.scopes = scopes;
        }

        public boolean isRequirePkce() {
            return requirePkce;
        }

        public void setRequirePkce(boolean requirePkce) {
            this.requirePkce = requirePkce;
        }

        public String getAccessTokenFormat() {
            return accessTokenFormat;
        }

        public void setAccessTokenFormat(String accessTokenFormat) {
            this.accessTokenFormat = accessTokenFormat;
        }

        public String getAccessTokenTtl() {
            return accessTokenTtl;
        }

        public void setAccessTokenTtl(String accessTokenTtl) {
            this.accessTokenTtl = accessTokenTtl;
        }

        public String getRefreshTokenTtl() {
            return refreshTokenTtl;
        }

        public void setRefreshTokenTtl(String refreshTokenTtl) {
            this.refreshTokenTtl = refreshTokenTtl;
        }

        public boolean isReuseRefreshTokens() {
            return reuseRefreshTokens;
        }

        public void setReuseRefreshTokens(boolean reuseRefreshTokens) {
            this.reuseRefreshTokens = reuseRefreshTokens;
        }
    }
}
