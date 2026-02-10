package com.authserver.oidc.logout;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

/**
 * Handles SAML LogoutResponse callback.
 * Retrieves logout context from Redis, invalidates session, and redirects to post_logout_redirect_uri.
 * Only enabled when Redis is available.
 */
@Component
@ConditionalOnProperty(name = "oidc.logout.enabled", havingValue = "true", matchIfMissing = true)
public class Saml2LogoutSuccessHandler implements LogoutSuccessHandler {
    
    private static final Logger log = LoggerFactory.getLogger(Saml2LogoutSuccessHandler.class);
    
    private final LogoutContextRepository logoutContextRepository;
    
    public Saml2LogoutSuccessHandler(LogoutContextRepository logoutContextRepository) {
        this.logoutContextRepository = logoutContextRepository;
    }
    
    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, 
                                Authentication authentication) throws IOException, ServletException {
        
        String relayState = request.getParameter("RelayState");
        log.debug("SAML logout callback with RelayState={}", relayState);
        
        // Retrieve logout context from Redis
        OidcLogoutContext context = logoutContextRepository.findAndDelete(relayState);
        
        // Invalidate HTTP session definitively
        HttpSession session = request.getSession(false);
        if (session != null) {
            log.debug("Invalidating session: {}", session.getId());
            session.invalidate();
        }
        
        // Build redirect URI
        String redirectUri;
        if (context != null && context.getPostLogoutRedirectUri() != null) {
            log.info("Redirecting to post_logout_redirect_uri: {}", context.getPostLogoutRedirectUri());
            
            UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(context.getPostLogoutRedirectUri());
            if (context.getState() != null) {
                builder.queryParam("state", context.getState());
            }
            redirectUri = builder.build().toUriString();
        } else {
            // Default: redirect to root
            log.info("No logout context found, redirecting to root");
            redirectUri = request.getContextPath().isEmpty() ? "/" : request.getContextPath();
        }
        
        response.sendRedirect(redirectUri);
    }
}
