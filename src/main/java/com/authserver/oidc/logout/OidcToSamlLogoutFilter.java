package com.authserver.oidc.logout;

import com.authserver.oidc.config.PropertiesRegisteredClientRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Filter that intercepts OIDC logout endpoint and redirects to SAML logout.
 * Must be registered BEFORE OidcLogoutEndpointFilter in the filter chain.
 * Only enabled when Redis is available.
 */
@Component
@ConditionalOnProperty(name = "oidc.logout.enabled", havingValue = "true", matchIfMissing = true)
public class OidcToSamlLogoutFilter extends OncePerRequestFilter {
    
    private static final Logger log = LoggerFactory.getLogger(OidcToSamlLogoutFilter.class);
    
    private final LogoutContextRepository logoutContextRepository;
    private final PropertiesRegisteredClientRepository clientRepository;
    private final JwtDecoder jwtDecoder;
    
    @Autowired
    public OidcToSamlLogoutFilter(
            LogoutContextRepository logoutContextRepository,
            @Autowired(required = false) PropertiesRegisteredClientRepository clientRepository,
            JwtDecoder jwtDecoder) {
        this.logoutContextRepository = logoutContextRepository;
        this.clientRepository = clientRepository;
        this.jwtDecoder = jwtDecoder;
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        
        // Only intercept /connect/logout
        if (!"/connect/logout".equals(request.getRequestURI())) {
            filterChain.doFilter(request, response);
            return;
        }
        
        String idTokenHint = request.getParameter("id_token_hint");
        String postLogoutRedirectUri = request.getParameter("post_logout_redirect_uri");
        String state = request.getParameter("state");
        
        log.debug("Intercepted OIDC logout: id_token_hint={}, post_logout_redirect_uri={}, state={}",
                idTokenHint != null ? "present" : "null", postLogoutRedirectUri, state);
        
        // Extract client_id from id_token_hint
        String clientId = extractClientId(idTokenHint);
        
        // Validate post_logout_redirect_uri if provided
        if (postLogoutRedirectUri != null && !postLogoutRedirectUri.isBlank()) {
            if (clientId == null) {
                sendError(response, "invalid_request", "id_token_hint required when post_logout_redirect_uri is provided");
                return;
            }
            
            if (clientRepository == null) {
                log.warn("PropertiesRegisteredClientRepository not available, skipping post_logout_redirect_uri validation");
            } else {
                RegisteredClient client = clientRepository.findByClientId(clientId);
                if (client == null) {
                    sendError(response, "invalid_client", "Client not found");
                    return;
                }
                
                // Validate against client's registered post_logout_redirect_uris
                if (!isValidPostLogoutRedirectUri(client, postLogoutRedirectUri)) {
                    log.warn("Invalid post_logout_redirect_uri for client {}: {}", clientId, postLogoutRedirectUri);
                    sendError(response, "invalid_request", "post_logout_redirect_uri not registered for this client");
                    return;
                }
            }
        }
        
        // Save logout context in Redis
        OidcLogoutContext context = new OidcLogoutContext(postLogoutRedirectUri, state, clientId);
        String logoutState = logoutContextRepository.save(context);
        
        log.info("Saved logout context with state={}, redirecting to SAML logout", logoutState);
        
        // Redirect to SAML logout with RelayState
        String samlLogoutUrl = buildSamlLogoutUrl(request, logoutState);
        response.sendRedirect(samlLogoutUrl);
    }
    
    private String extractClientId(String idTokenHint) {
        if (idTokenHint == null || idTokenHint.isBlank()) {
            return null;
        }
        
        try {
            Jwt jwt = jwtDecoder.decode(idTokenHint);
            List<String> audience = jwt.getAudience();
            return (audience != null && !audience.isEmpty()) ? audience.get(0) : null;
        } catch (Exception e) {
            log.warn("Failed to decode id_token_hint: {}", e.getMessage());
            return null;
        }
    }
    
    private boolean isValidPostLogoutRedirectUri(RegisteredClient client, String uri) {
        // Check if client has configured post_logout_redirect_uris
        if (client.getPostLogoutRedirectUris() != null && !client.getPostLogoutRedirectUris().isEmpty()) {
            return client.getPostLogoutRedirectUris().contains(uri);
        }
        
        // Fallback: allow redirect_uris as post_logout_redirect_uris for backward compatibility
        return client.getRedirectUris().contains(uri) || 
               client.getRedirectUris().stream().anyMatch(registeredUri -> 
                   uri.startsWith(registeredUri.replaceAll("/callback$", "")));
    }
    
    private String buildSamlLogoutUrl(HttpServletRequest request, String relayState) {
        String contextPath = request.getContextPath();
        String baseUrl = UriComponentsBuilder.fromHttpUrl(
                request.getScheme() + "://" + request.getServerName() + 
                (request.getServerPort() != 80 && request.getServerPort() != 443 ? ":" + request.getServerPort() : "")
        ).path(contextPath).build().toUriString();
        
        // SAML logout endpoint with registrationId and RelayState
        return baseUrl + "/saml2/logout/bet?RelayState=" + 
               URLEncoder.encode(relayState, StandardCharsets.UTF_8);
    }
    
    private void sendError(HttpServletResponse response, String error, String description) throws IOException {
        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        response.setContentType("application/json");
        response.getWriter().write(String.format(
            "{\"error\":\"%s\",\"error_description\":\"%s\"}",
            error, description
        ));
    }
}
