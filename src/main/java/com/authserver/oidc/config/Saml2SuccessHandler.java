package com.authserver.oidc.config;

import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Handler que se ejecuta automáticamente después de que SAML2 autentica exitosamente.
 * 
 * Este componente se engacha en la cadena de seguridad estándar (Saml2WebSsoAuthenticationFilter)
 * y NO expone ningún endpoint.
 * 
 * Su propósito:
 * 1. Almacenar el Session ID (sid) en sesión para el ID Token
 * 2. Guardar claims de SAML (attributes, auth_time, acr, amr) para OIDC
 * 3. Preservar el contexto de autenticación SAML para uso posterior
 * 
 * Los datos guardados son consumidos por:
 * - OidcAuthorizationServerConfig.addSessionIdClaim() → sid en ID Token
 * - OidcAuthorizationServerConfig.applySamlClaims() → claims de SAML en ID Token
 */
@Component
@ConditionalOnProperty(name = "saml.enabled", havingValue = "true", matchIfMissing = true)
public class Saml2SuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    public Saml2SuccessHandler() {
        // Redirigir a /oauth2/authorize después de autenticar con SAML
        setDefaultTargetUrl("/oauth2/authorize");
        setAlwaysUseDefaultTargetUrl(false);
    }

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) throws ServletException, IOException {

        if (authentication instanceof Saml2Authentication samlAuth) {
            HttpSession session = request.getSession();
            String sessionId = session.getId();
            
            // Extract principal from authentication
            Object principalObj = samlAuth.getPrincipal();
            if (!(principalObj instanceof Saml2AuthenticatedPrincipal)) {
                super.onAuthenticationSuccess(request, response, authentication);
                return;
            }
            
            Saml2AuthenticatedPrincipal principal = (Saml2AuthenticatedPrincipal) principalObj;
            String nameId = principal.getName();

            // 1. Guardar Session ID (sid) para el ID Token
            session.setAttribute("sid", sessionId);
            
            // 2. Guardar información básica de SAML
            session.setAttribute("saml_user_id", nameId);
            session.setAttribute("saml_authenticated", true);
            session.setAttribute("saml_auth_time", Instant.now().getEpochSecond());
            
            // 3. Guardar todos los atributos SAML para claims del ID Token
            Map<String, List<Object>> samlAttributes = new HashMap<>(principal.getAttributes());
            session.setAttribute("saml_attributes", samlAttributes);
            
            // 4. Guardar authentication context (ACR) si está disponible
            String sessionIndex = principal.getSessionIndexes().isEmpty() 
                ? null 
                : principal.getSessionIndexes().iterator().next();
            if (sessionIndex != null) {
                session.setAttribute("saml_session_index", sessionIndex);
            }

            // 5. Log para debugging
            System.out.println("[SAML_SUCCESS] User authenticated: " + nameId);
            System.out.println("[SAML_SUCCESS] Session ID (sid): " + sessionId);
            System.out.println("[SAML_SUCCESS] SAML attributes: " + samlAttributes.keySet());
        }

        // Delegar al handler estándar para redirigir correctamente
        super.onAuthenticationSuccess(request, response, authentication);
    }
}
