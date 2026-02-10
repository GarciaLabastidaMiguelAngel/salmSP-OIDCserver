package com.authserver.oidc.test.util;

import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;
import java.util.UUID;

/**
 * Test utility for building OAuth2Authorization instances with realistic tokens.
 * Simplifies test setup by using Jackson serialization internally.
 */
public class OAuth2AuthorizationTestBuilder {

    private String registeredClientId = "test-client";
    private String principalName = "test-user";
    private Set<String> authorizedScopes = Set.of("openid", "profile");
    
    // Authorization Request
    private String redirectUri = "http://localhost:8080/callback";
    private String state = "test-state";
    
    // Authorization Code
    private String authorizationCode;
    private Instant codeIssuedAt;
    private Instant codeExpiresAt;
    
    // Access Token
    private String accessToken;
    private Instant accessTokenIssuedAt;
    private Instant accessTokenExpiresAt;
    
    // Refresh Token
    private String refreshToken;
    private Instant refreshTokenIssuedAt;
    private Instant refreshTokenExpiresAt;

    public static OAuth2AuthorizationTestBuilder builder() {
        return new OAuth2AuthorizationTestBuilder();
    }

    public OAuth2AuthorizationTestBuilder registeredClientId(String registeredClientId) {
        this.registeredClientId = registeredClientId;
        return this;
    }

    public OAuth2AuthorizationTestBuilder principalName(String principalName) {
        this.principalName = principalName;
        return this;
    }

    public OAuth2AuthorizationTestBuilder redirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
        return this;
    }

    public OAuth2AuthorizationTestBuilder state(String state) {
        this.state = state;
        return this;
    }

    public OAuth2AuthorizationTestBuilder authorizationCode(String code) {
        this.authorizationCode = code;
        this.codeIssuedAt = Instant.now();
        this.codeExpiresAt = this.codeIssuedAt.plus(5, ChronoUnit.MINUTES);
        return this;
    }

    public OAuth2AuthorizationTestBuilder authorizationCodeExpiresInSeconds(String code, long seconds) {
        this.authorizationCode = code;
        this.codeIssuedAt = Instant.now();
        this.codeExpiresAt = this.codeIssuedAt.plus(seconds, ChronoUnit.SECONDS);
        return this;
    }

    public OAuth2AuthorizationTestBuilder authorizationCode(String code, Instant issuedAt, Instant expiresAt) {
        this.authorizationCode = code;
        this.codeIssuedAt = issuedAt;
        this.codeExpiresAt = expiresAt;
        return this;
    }

    public OAuth2AuthorizationTestBuilder accessToken(String token) {
        this.accessToken = token;
        this.accessTokenIssuedAt = Instant.now();
        this.accessTokenExpiresAt = this.accessTokenIssuedAt.plus(1, ChronoUnit.HOURS);
        return this;
    }

    public OAuth2AuthorizationTestBuilder accessTokenExpiresInSeconds(String token, long seconds) {
        this.accessToken = token;
        this.accessTokenIssuedAt = Instant.now();
        this.accessTokenExpiresAt = this.accessTokenIssuedAt.plus(seconds, ChronoUnit.SECONDS);
        return this;
    }

    public OAuth2AuthorizationTestBuilder accessToken(String token, Instant issuedAt, Instant expiresAt) {
        this.accessToken = token;
        this.accessTokenIssuedAt = issuedAt;
        this.accessTokenExpiresAt = expiresAt;
        return this;
    }

    public OAuth2AuthorizationTestBuilder refreshToken(String token) {
        this.refreshToken = token;
        this.refreshTokenIssuedAt = Instant.now();
        this.refreshTokenExpiresAt = this.refreshTokenIssuedAt.plus(30, ChronoUnit.DAYS);
        return this;
    }

    public OAuth2AuthorizationTestBuilder refreshTokenExpiresInSeconds(String token, long seconds) {
        this.refreshToken = token;
        this.refreshTokenIssuedAt = Instant.now();
        this.refreshTokenExpiresAt = this.refreshTokenIssuedAt.plus(seconds, ChronoUnit.SECONDS);
        return this;
    }

    public OAuth2AuthorizationTestBuilder refreshToken(String token, Instant issuedAt, Instant expiresAt) {
        this.refreshToken = token;
        this.refreshTokenIssuedAt = issuedAt;
        this.refreshTokenExpiresAt = expiresAt;
        return this;
    }

    public OAuth2AuthorizationTestBuilder authorizedScopes(Set<String> scopes) {
        this.authorizedScopes = scopes;
        return this;
    }

    /**
     * Builds an OAuth2Authorization by creating a minimal auth and enriching with tokens.
     * Uses OAuth2Authorization.from() to construct a mutable builder.
     */
    public OAuth2Authorization build() {
        String id = UUID.randomUUID().toString();

        RegisteredClient registeredClient = RegisteredClient.withId(id)
            .clientId(registeredClientId)
            .clientSecret("test-secret")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri(redirectUri)
            .scope("openid")
            .scope("profile")
            .clientSettings(ClientSettings.builder().build())
            .tokenSettings(TokenSettings.builder().build())
            .build();

        OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient)
            .principalName(principalName)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizedScopes(authorizedScopes);

        OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
            .clientId(registeredClientId)
            .redirectUri(redirectUri)
            .scopes(authorizedScopes)
            .state(state)
            .authorizationUri("http://localhost:8080/oauth2/authorize")
            .build();

        builder.attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest);

        if (authorizationCode != null) {
            OAuth2AuthorizationCode code = new OAuth2AuthorizationCode(
                authorizationCode,
                codeIssuedAt,
                codeExpiresAt
            );
            builder.token(code);
        }

        if (accessToken != null) {
            OAuth2AccessToken token = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                accessToken,
                accessTokenIssuedAt,
                accessTokenExpiresAt,
                authorizedScopes
            );
            builder.accessToken(token);
        }

        if (refreshToken != null) {
            OAuth2RefreshToken token = new OAuth2RefreshToken(
                refreshToken,
                refreshTokenIssuedAt,
                refreshTokenExpiresAt
            );
            builder.refreshToken(token);
        }

        return builder.build();
    }

    /**
     * Convenience method: builds authorization with code + access token (typical OAuth2 flow).
     */
    public static OAuth2Authorization buildWithCodeAndAccessToken() {
        return builder()
                .authorizationCode("test-code-" + UUID.randomUUID())
                .accessToken("test-access-" + UUID.randomUUID())
                .build();
    }

    /**
     * Convenience method: builds authorization with code + access + refresh tokens.
     */
    public static OAuth2Authorization buildWithAllTokens() {
        return builder()
                .authorizationCode("test-code-" + UUID.randomUUID())
                .accessToken("test-access-" + UUID.randomUUID())
                .refreshToken("test-refresh-" + UUID.randomUUID())
                .build();
    }
}
