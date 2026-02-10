package com.authserver.oidc.config;

import com.authserver.oidc.config.properties.OidcClientsProperties;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.logging.Logger;

/**
 * In-memory RegisteredClientRepository backed by properties.
 * Loads clients from OidcClientsProperties and keeps them in memory.
 * NO database persistence; clients defined in application.yml / environment variables.
 * Thread-safe for multi-pod Kubernetes: each pod loads same clients from config.
 * 
 * NOTE: NO @Repository annotation - instantiated via @Bean method in OidcAuthorizationServerConfig.
 */
public class PropertiesRegisteredClientRepository implements RegisteredClientRepository {

    private static final Logger logger = Logger.getLogger(PropertiesRegisteredClientRepository.class.getName());

    private final OidcClientsProperties clientsProperties;
    private final Map<String, RegisteredClient> clientsById = new HashMap<>();
    private final Map<String, RegisteredClient> clientsByClientId = new HashMap<>();

    public PropertiesRegisteredClientRepository(OidcClientsProperties clientsProperties) {
        this.clientsProperties = clientsProperties;
        loadClientsFromProperties();
    }

    /**
     * Load all clients from properties into memory.
     * Called at startup; idempotent.
     */
    private void loadClientsFromProperties() {
        try {
            if (clientsProperties.getClients() == null || clientsProperties.getClients().isEmpty()) {
                throw new IllegalArgumentException("No clients defined in oidc.clients");
            }

            for (OidcClientsProperties.ClientProperties clientProp : clientsProperties.getClients()) {
                RegisteredClient client = buildRegisteredClient(clientProp);
                clientsById.put(client.getId(), client);
                clientsByClientId.put(client.getClientId(), client);
                logger.info("[STARTUP] Loaded client: " + client.getClientId());
            }

            logger.info("[STARTUP] Loaded " + clientsById.size() + " clients from properties");
        } catch (Exception e) {
            logger.severe("Failed to load clients from properties: " + e.getMessage());
            throw new RuntimeException("Failed to initialize RegisteredClientRepository", e);
        }
    }

    /**
     * Build RegisteredClient from OidcClientsProperties.ClientProperties.
     */
    private RegisteredClient buildRegisteredClient(OidcClientsProperties.ClientProperties prop) {
        RegisteredClient.Builder builder = RegisteredClient
            .withId(UUID.randomUUID().toString())
            .clientId(prop.getClientId())
            .clientSecret(prop.getClientSecret())
            .clientName(prop.getClientName());

        // Client authentication methods
        if (prop.getClientAuthMethods() != null && !prop.getClientAuthMethods().isEmpty()) {
            prop.getClientAuthMethods().forEach(method ->
                builder.clientAuthenticationMethod(new ClientAuthenticationMethod(method))
            );
        }

        // Authorization grant types
        if (prop.getGrantTypes() != null && !prop.getGrantTypes().isEmpty()) {
            prop.getGrantTypes().forEach(grantType ->
                builder.authorizationGrantType(new AuthorizationGrantType(grantType))
            );
        }

        // Redirect URIs
        if (prop.getRedirectUris() != null && !prop.getRedirectUris().isEmpty()) {
            prop.getRedirectUris().forEach(builder::redirectUri);
        }

        // Post-logout redirect URIs
        if (prop.getPostLogoutRedirectUris() != null && !prop.getPostLogoutRedirectUris().isEmpty()) {
            prop.getPostLogoutRedirectUris().forEach(builder::postLogoutRedirectUri);
        }

        // Scopes
        if (prop.getScopes() != null && !prop.getScopes().isEmpty()) {
            prop.getScopes().forEach(builder::scope);
        }

        // Token Settings
        TokenSettings.Builder tokenSettingsBuilder = TokenSettings.builder();

        // Parse ISO 8601 durations
        Duration accessTokenTTL = Duration.parse(prop.getAccessTokenTtl());
        Duration refreshTokenTTL = Duration.parse(prop.getRefreshTokenTtl());

        tokenSettingsBuilder
            .accessTokenTimeToLive(accessTokenTTL)
            .refreshTokenTimeToLive(refreshTokenTTL)
            .reuseRefreshTokens(prop.isReuseRefreshTokens());

        builder.tokenSettings(tokenSettingsBuilder.build());

        // Client Settings
        ClientSettings.Builder clientSettingsBuilder = ClientSettings.builder()
            .requireProofKey(prop.isRequirePkce());
        builder.clientSettings(clientSettingsBuilder.build());

        return builder.build();
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        if (registeredClient == null) {
            throw new IllegalArgumentException("RegisteredClient cannot be null");
        }
        // Properties-based; no persistence
        logger.warning("save() called on PropertiesRegisteredClientRepository (no-op); clients are read-only from properties");
    }

    @Override
    public RegisteredClient findById(String id) {
        if (id == null || id.isBlank()) {
            return null;
        }
        return clientsById.get(id);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        if (clientId == null || clientId.isBlank()) {
            return null;
        }
        return clientsByClientId.get(clientId);
    }
}
