package com.authserver.oidc.config;

import com.authserver.oidc.logout.OidcToSamlLogoutFilter;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * OIDC Authorization Server Configuration (Spring Authorization Server 1.3.x)
 * 
 * Provides standard OAuth2/OIDC endpoints:
 * - GET  /oauth2/authorize              (Authorization Code flow)
 * - POST /oauth2/token                  (Token exchange)
 * - GET  /oauth2/jwks                   (Public keys)
 * - GET  /.well-known/openid-configuration (OIDC Discovery)
 * - GET  /userinfo                      (User info endpoint)
 * 
 * Token Issuance:
 * - access_token: JWT (self-contained, configurable lifetime)
 * - id_token: JWT with OIDC claims (includes sid, amr, acr)
 * - refresh_token: Opaque (configurable lifetime, reusable)
 * 
 * Session Management:
 * - Session ID (sid) automatically resolved from HTTP session
 * - Fallback strategy: explicit sid attribute → current HTTP session
 * - No artificial session creation
 * 
 * SAML Integration:
 * - Maps SAML attributes to OIDC claims
 * - Supports ACR, AMR, auth_time from SAML
 * - Maintains compatibility with Saml2SuccessHandler
 * 
 * Storage:
 * - Clients: Loaded from properties (OidcClientsProperties, no database)
 * - Authorizations: H2 database via JdbcOAuth2AuthorizationService
 * - Consents: Disabled (not required for this use case)
 * 
 * Single-Pod Mode:
 * - H2 embedded (in-memory) for Friends & Family deployment
 * - No multi-pod support (no Redis, no shared state)
 */
@Configuration
public class OidcAuthorizationServerConfig {

    @Value("${saml.enabled:true}")
    private boolean samlEnabled;
    
    private final ApplicationContext applicationContext;
    
    public OidcAuthorizationServerConfig(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }
    
    // RSA key pair for signing JWTs (generated at startup)
    private static final RSAKey RSA_KEY;
    
    static {
        try {
            RSA_KEY = new RSAKeyGenerator(2048)
                .keyID(UUID.randomUUID().toString())
                .generate();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate RSA key", e);
        }
    }
    
    /**
     * Order(1): Authorization Server filter chain (higher priority than application security).
     * Uses Spring Authorization Server's default security configuration which:
     * - Registers all OAuth2 endpoints (/oauth2/authorize, /oauth2/token, /oauth2/jwks, etc.)
     * - Enables OIDC endpoints (/.well-known/openid-configuration, /userinfo, etc.)
     * - Protects endpoints with appropriate authentication
     */
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        // Apply Spring Authorization Server default security
        // This automatically registers all OAuth2/OIDC endpoints
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        // Get the OAuth2 configurer to customize OIDC settings
        var authorizationServerConfigurer = http.getConfigurer(
            org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer.class
        );

        // Enable all OIDC endpoints with custom userInfo mapper
        authorizationServerConfigurer.oidc(oidc -> oidc
            .userInfoEndpoint(userInfo -> userInfo
                .userInfoMapper(this::createUserInfo)
            )
            .providerConfigurationEndpoint(Customizer.withDefaults())
            .logoutEndpoint(Customizer.withDefaults())
        );
        // Configure OAuth2 Resource Server for JWT validation (needed for /userinfo endpoint)
        http.oauth2ResourceServer(oauth2 -> oauth2
            .jwt(Customizer.withDefaults())
        );

        // Add custom logout filter BEFORE LogoutFilter (if enabled) - lazy lookup to avoid circular dependency
        try {
            OidcToSamlLogoutFilter filter = applicationContext.getBean(OidcToSamlLogoutFilter.class);
            http.addFilterBefore(filter, LogoutFilter.class);
        } catch (Exception e) {
            // Filter not available (e.g., in tests), skip
        }

        // Handle unauthenticated requests by redirecting to SAML2 login (only when SAML enabled)
        // Handle unauthenticated requests by redirecting to SAML2 login (only when SAML enabled)
        if (samlEnabled) {
            http.exceptionHandling(exceptions ->
                exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/saml2/authenticate/bet"))
            );
        }

        return http.build();
    }
    
    /**
     * Create OidcUserInfo from SAML2 authentication context.
     * Extracts user attributes from the SAML2 principal and maps them to OIDC claims.
     */
    private OidcUserInfo createUserInfo(OidcUserInfoAuthenticationContext context) {
        OAuth2Authorization authorization = context.getAuthorization();
        
        // Build claims map
        Map<String, Object> claims = new HashMap<>();
        
        // Get the principal name (NameID from SAML)
        if (authorization != null && authorization.getPrincipalName() != null) {
            String username = authorization.getPrincipalName();
            claims.put("sub", username);
            claims.put("name", username);
            claims.put("preferred_username", username);
            
            // Try to extract email from username if it looks like an email
            if (username.contains("@")) {
                claims.put("email", username);
                claims.put("email_verified", true);
            }
        }
        
        // Try to extract additional SAML attributes
        if (authorization != null) {
            Object principal = authorization.getAttribute("java.security.Principal");
            if (principal instanceof Saml2AuthenticatedPrincipal) {
                Saml2AuthenticatedPrincipal saml2Principal = (Saml2AuthenticatedPrincipal) principal;
                
                // Map common SAML attributes to OIDC claims
                saml2Principal.getAttributes().forEach((key, values) -> {
                    if (!values.isEmpty()) {
                        Object value = values.size() == 1 ? values.get(0) : values;
                        
                        switch (key.toLowerCase()) {
                            case "email":
                            case "emailaddress":
                                claims.put("email", value);
                                claims.put("email_verified", true);
                                break;
                            case "givenname":
                            case "firstname":
                                claims.put("given_name", value);
                                break;
                            case "surname":
                            case "lastname":
                                claims.put("family_name", value);
                                break;
                            case "displayname":
                                claims.put("name", value);
                                break;
                            default:
                                // Include other attributes as-is
                                claims.put(key, value);
                        }
                    }
                });
            }
        }
        
        return new OidcUserInfo(claims);
    }

    /**
     * Customize ID Token and Access Token claims with security and session context.
     * Handles session ID with automatic fallback to HTTP session.
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            var claims = context.getClaims();
            boolean isIdToken = context.getTokenType() != null && 
                               context.getTokenType().getValue().equals("id_token");

            // Common claims for all tokens
            claims.claim("jti", UUID.randomUUID().toString());

            // ID Token specific claims
            if (isIdToken) {
                // Authorized Party (azp) - client that requested the token
                if (context.getRegisteredClient() != null) {
                    claims.claim("azp", context.getRegisteredClient().getClientId());
                }

                // Scopes
                Set<String> scopes = context.getAuthorizedScopes();
                if (scopes != null && !scopes.isEmpty()) {
                    claims.claim("scope", String.join(" ", scopes));
                }

                // Nonce (OIDC replay protection)
                OAuth2Authorization authorization = context.getAuthorization();
                if (authorization != null) {
                    Object nonce = authorization.getAttribute("nonce");
                    if (nonce instanceof String) {
                        claims.claim("nonce", (String) nonce);
                    }
                }

                // Session ID (sid) - critical for session management
                addSessionIdClaim(claims, context);

                // Roles from authorities
                if (context.getPrincipal() != null && context.getPrincipal().getAuthorities() != null) {
                    List<String> roles = new ArrayList<>();
                    context.getPrincipal().getAuthorities().forEach(a -> roles.add(a.getAuthority()));
                    if (!roles.isEmpty()) {
                        claims.claim("roles", roles);
                    }
                }

                // SAML claims mapping
                if (context.getPrincipal() instanceof Saml2Authentication) {
                    applySamlClaims((Saml2Authentication) context.getPrincipal(), claims);
                }
            }
        };
    }

    /**
     * Add session ID claim with priority strategy:
     * 1. Check session attribute "sid" (set by Saml2SuccessHandler after SAML auth)
     * 2. Check authorization attributes (explicit sid from OAuth2Authorization)
     * 3. Fallback to current HTTP session ID (if available)
     */
    private void addSessionIdClaim(org.springframework.security.oauth2.jwt.JwtClaimsSet.Builder claims, 
                                   JwtEncodingContext context) {
        String sessionId = null;

        // Priority 1: Check session attribute (set by Saml2SuccessHandler)
        sessionId = resolveSessionAttribute("sid");
        
        // Priority 2: Try to get sid from authorization attributes (explicit)
        if (sessionId == null) {
            OAuth2Authorization authorization = context.getAuthorization();
            if (authorization != null) {
                Object sidAttr = authorization.getAttribute("sid");
                if (sidAttr instanceof String) {
                    sessionId = (String) sidAttr;
                }
            }
        }

        // Priority 3: Fallback to current HTTP session
        if (sessionId == null) {
            sessionId = resolveCurrentSessionId();
        }

        // Set claim if we have a valid session ID
        if (sessionId != null && !sessionId.isBlank()) {
            claims.claim("sid", sessionId);
        }
    }
    
    /**
     * Resolve attribute from current HTTP session.
     * Returns null if no session exists or attribute is not found.
     */
    private String resolveSessionAttribute(String attributeName) {
        try {
            if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attrs) {
                var request = attrs.getRequest();
                if (request != null) {
                    var session = request.getSession(false);
                    if (session != null) {
                        Object attr = session.getAttribute(attributeName);
                        if (attr instanceof String) {
                            return (String) attr;
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Ignore - attribute resolution is optional
        }
        return null;
    }

    /**
     * Resolve current HTTP session ID from request context.
     * Returns null if no session exists (doesn't create one).
     */
    private String resolveCurrentSessionId() {
        try {
            if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attrs) {
                var request = attrs.getRequest();
                if (request != null) {
                    var session = request.getSession(false); // Don't create new session
                    if (session != null) {
                        return session.getId();
                    }
                }
            }
        } catch (Exception e) {
            // Ignore - session resolution is optional
        }
        return null;
    }

    /**
     * Apply SAML claims to ID Token with dual-source strategy:
     * 1. Try to load SAML attributes from session (set by Saml2SuccessHandler)
     * 2. Fallback to authentication principal if session data not available
     * 
     * This approach ensures claims are available even if authentication context is lost.
     */
    private void applySamlClaims(Saml2Authentication samlAuth, 
                                org.springframework.security.oauth2.jwt.JwtClaimsSet.Builder claims) {
        
        // Strategy 1: Try to load SAML attributes from session (preferred)
        Map<String, List<Object>> sessionAttributes = loadSamlAttributesFromSession();
        if (sessionAttributes != null && !sessionAttributes.isEmpty()) {
            applySamlClaimsFromSessionAttributes(sessionAttributes, claims);
            
            // Add auth_time from session if available
            String authTimeStr = resolveSessionAttribute("saml_auth_time");
            if (authTimeStr != null) {
                try {
                    claims.claim("auth_time", Long.parseLong(authTimeStr));
                } catch (NumberFormatException e) {
                    // Ignore invalid format
                }
            }
            return;
        }
        
        // Strategy 2: Fallback to authentication principal
        if (samlAuth == null || samlAuth.getPrincipal() == null) {
            return;
        }

        Object principalObj = samlAuth.getPrincipal();
        if (!(principalObj instanceof Saml2AuthenticatedPrincipal)) {
            return;
        }

        Saml2AuthenticatedPrincipal principal = (Saml2AuthenticatedPrincipal) principalObj;
        applySamlClaimsFromPrincipal(principal, claims);
    }
    
    /**
     * Load SAML attributes from HTTP session (stored by Saml2SuccessHandler).
     */
    @SuppressWarnings("unchecked")
    private Map<String, List<Object>> loadSamlAttributesFromSession() {
        try {
            if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attrs) {
                var request = attrs.getRequest();
                if (request != null) {
                    var session = request.getSession(false);
                    if (session != null) {
                        Object attr = session.getAttribute("saml_attributes");
                        if (attr instanceof Map) {
                            return (Map<String, List<Object>>) attr;
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Ignore - fallback to principal
        }
        return null;
    }
    
    /**
     * Apply SAML claims from session attributes (Map<String, List<Object>>).
     */
    private void applySamlClaimsFromSessionAttributes(Map<String, List<Object>> attributes, 
                                                     org.springframework.security.oauth2.jwt.JwtClaimsSet.Builder claims) {
        // Standard OIDC claims from SAML attributes
        putIfPresent(claims, "preferred_username", 
            firstValue(attributes, "preferred_username", "username", "uid"));
        putIfPresent(claims, "name", 
            firstValue(attributes, "name", "displayname", "displayName"));
        putIfPresent(claims, "given_name", 
            firstValue(attributes, "givenname", "firstname", "given_name", "givenName"));
        putIfPresent(claims, "family_name", 
            firstValue(attributes, "surname", "lastname", "family_name", "familyName"));

        // Email with verification flag
        String email = firstValue(attributes, "email", "emailaddress", "mail", "emailAddress");
        if (email != null && !email.isBlank()) {
            claims.claim("email", email);
            claims.claim("email_verified", true);
        }

        // ACR - Authentication Context Class Reference
        String acr = firstValue(attributes, "acr", "authncontextclassref", 
            "authentication_context_class_ref", "AuthnContextClassRef");
        putIfPresent(claims, "acr", acr);

        // AMR - Authentication Methods Reference
        List<String> amr = resolveAmrFromAttributes(attributes, acr);
        if (!amr.isEmpty()) {
            claims.claim("amr", amr);
        }
    }
    
    /**
     * Apply SAML claims from Saml2AuthenticatedPrincipal (fallback).
     */
    private void applySamlClaimsFromPrincipal(Saml2AuthenticatedPrincipal principal, 
                                             org.springframework.security.oauth2.jwt.JwtClaimsSet.Builder claims) {

        // Standard OIDC claims from SAML attributes
        putIfPresent(claims, "preferred_username", 
            firstAttributeValue(principal, "preferred_username", "username", "uid"));
        putIfPresent(claims, "name", 
            firstAttributeValue(principal, "name", "displayname", "displayName"));
        putIfPresent(claims, "given_name", 
            firstAttributeValue(principal, "givenname", "firstname", "given_name", "givenName"));
        putIfPresent(claims, "family_name", 
            firstAttributeValue(principal, "surname", "lastname", "family_name", "familyName"));

        // Email with verification flag
        String email = firstAttributeValue(principal, "email", "emailaddress", "mail", "emailAddress");
        if (email != null && !email.isBlank()) {
            claims.claim("email", email);
            claims.claim("email_verified", true);
        }

        // ACR - Authentication Context Class Reference
        String acr = firstAttributeValue(principal, "acr", "authncontextclassref", 
            "authentication_context_class_ref", "AuthnContextClassRef");
        putIfPresent(claims, "acr", acr);

        // AMR - Authentication Methods Reference
        List<String> amr = resolveAmr(principal, acr);
        if (!amr.isEmpty()) {
            claims.claim("amr", amr);
        }

        // auth_time - Time of authentication
        String authTime = firstAttributeValue(principal, "auth_time", "authn_instant", 
            "authenticationinstant", "AuthnInstant");
        if (authTime != null && !authTime.isBlank()) {
            try {
                claims.claim("auth_time", Long.parseLong(authTime));
            } catch (NumberFormatException e) {
                // Ignore invalid auth_time format
            }
        }
    }

    /**
     * Resolve Authentication Methods Reference (AMR) from SAML attributes or ACR.
     * Returns list of authentication methods used (e.g., ["pwd"], ["mfa"]).
     */
    private List<String> resolveAmr(Saml2AuthenticatedPrincipal principal, String acr) {
        List<String> amr = new ArrayList<>();

        if (principal == null) {
            return amr;
        }

        // Try to get AMR from SAML attributes
        Object amrAttr = findAttribute(principal, "amr", "authnmethod", 
            "authenticationmethod", "authentication_method", "AuthnMethod");
        
        if (amrAttr instanceof Collection) {
            for (Object v : (Collection<?>) amrAttr) {
                if (v != null && !v.toString().isBlank()) {
                    amr.add(v.toString());
                }
            }
        } else if (amrAttr != null && !amrAttr.toString().isBlank()) {
            amr.add(amrAttr.toString());
        }

        // Fallback: infer from ACR if no explicit AMR
        if (amr.isEmpty() && acr != null && !acr.isBlank()) {
            String acrLower = acr.toLowerCase();
            if (acrLower.contains("mfa") || acrLower.contains("multifactor")) {
                amr.add("mfa");
            } else if (acrLower.contains("otp")) {
                amr.add("otp");
            } else if (acrLower.contains("password") || acrLower.contains("pwd")) {
                amr.add("pwd");
            }
        }

        return amr;
    }
    
    /**
     * Resolve AMR from session attributes Map.
     */
    private List<String> resolveAmrFromAttributes(Map<String, List<Object>> attributes, String acr) {
        List<String> amr = new ArrayList<>();

        // Try to get AMR from SAML attributes
        Object amrAttr = findAttributeInMap(attributes, "amr", "authnmethod", 
            "authenticationmethod", "authentication_method", "AuthnMethod");
        
        if (amrAttr instanceof Collection) {
            for (Object v : (Collection<?>) amrAttr) {
                if (v != null && !v.toString().isBlank()) {
                    amr.add(v.toString());
                }
            }
        } else if (amrAttr != null && !amrAttr.toString().isBlank()) {
            amr.add(amrAttr.toString());
        }

        // Fallback: infer from ACR if no explicit AMR
        if (amr.isEmpty() && acr != null && !acr.isBlank()) {
            String acrLower = acr.toLowerCase();
            if (acrLower.contains("mfa") || acrLower.contains("multifactor")) {
                amr.add("mfa");
            } else if (acrLower.contains("otp")) {
                amr.add("otp");
            } else if (acrLower.contains("password") || acrLower.contains("pwd")) {
                amr.add("pwd");
            }
        }

        return amr;
    }
    
    /**
     * Find attribute in Map by multiple possible key names (case-insensitive).
     */
    private Object findAttributeInMap(Map<String, List<Object>> attributes, String... keys) {
        if (attributes == null) {
            return null;
        }

        for (String key : keys) {
            for (Map.Entry<String, List<Object>> entry : attributes.entrySet()) {
                if (entry.getKey() != null && entry.getKey().equalsIgnoreCase(key)) {
                    List<Object> values = entry.getValue();
                    if (values != null && !values.isEmpty()) {
                        return values.size() == 1 ? values.get(0) : values;
                    }
                }
            }
        }
        return null;
    }
    
    /**
     * Get first non-blank string value from session attributes Map.
     */
    private String firstValue(Map<String, List<Object>> attributes, String... keys) {
        Object value = findAttributeInMap(attributes, keys);
        
        if (value instanceof Collection) {
            for (Object v : (Collection<?>) value) {
                if (v != null && !v.toString().isBlank()) {
                    return v.toString();
                }
            }
            return null;
        }
        
        return (value != null && !value.toString().isBlank()) ? value.toString() : null;
    }

    /**
     * Find SAML attribute by multiple possible key names (case-insensitive).
     */
    private Object findAttribute(Saml2AuthenticatedPrincipal principal, String... keys) {
        if (principal == null || principal.getAttributes() == null) {
            return null;
        }

        for (String key : keys) {
            for (Map.Entry<String, List<Object>> entry : principal.getAttributes().entrySet()) {
                if (entry.getKey() != null && entry.getKey().equalsIgnoreCase(key)) {
                    List<Object> values = entry.getValue();
                    if (values != null && !values.isEmpty()) {
                        return values.size() == 1 ? values.get(0) : values;
                    }
                }
            }
        }
        return null;
    }

    /**
     * Get first non-blank string value from SAML attribute.
     */
    private String firstAttributeValue(Saml2AuthenticatedPrincipal principal, String... keys) {
        Object value = findAttribute(principal, keys);
        
        if (value instanceof Collection) {
            for (Object v : (Collection<?>) value) {
                if (v != null && !v.toString().isBlank()) {
                    return v.toString();
                }
            }
            return null;
        }
        
        return (value != null && !value.toString().isBlank()) ? value.toString() : null;
    }

    /**
     * Add claim only if value is present and non-blank.
     */
    private void putIfPresent(org.springframework.security.oauth2.jwt.JwtClaimsSet.Builder claims, 
                             String name, String value) {
        if (value != null && !value.isBlank()) {
            claims.claim(name, value);
        }
    }
    
    /**
     * OAuth2AuthorizationService: JDBC-backed with H2.
     * Persists authorization state (codes, tokens, session context) in H2 database.
     * Supports findByToken for token exchange and introspection.
     */
    @Bean
    public OAuth2AuthorizationService authorizationService(
            org.springframework.jdbc.core.JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository) {
        return new org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService(
                jdbcTemplate, registeredClientRepository);
    }
    
    /**
     * Registered Client Repository: Loaded from properties.
     * Clients are defined in application.yml (oidc.clients).
     * NO database persistence; read-only configuration.
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository(
            com.authserver.oidc.config.properties.OidcClientsProperties clientsProperties) {
        return new PropertiesRegisteredClientRepository(clientsProperties);
    }
    
    /**
     * Authorization Server Settings.
     * Issuer URI from properties (oidc.issuer).
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings(
            com.authserver.oidc.config.properties.OidcClientsProperties clientsProperties) {
        return AuthorizationServerSettings.builder()
            .issuer(clientsProperties.getIssuer())
            .build();
    }
    
    /**
     * JWK Source: holds RSA public key for /oauth2/jwks endpoint.
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        JWKSet jwkSet = new JWKSet(RSA_KEY);
        return new ImmutableJWKSet<>(jwkSet);
    }
    
    /**
     * JWT Decoder for validating JWTs (used internally by Authorization Server).
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) throws Exception {
        return NimbusJwtDecoder.withPublicKey(RSA_KEY.toRSAPublicKey()).build();
    }
}
