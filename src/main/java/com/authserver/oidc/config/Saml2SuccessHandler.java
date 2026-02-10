package com.authserver.oidc.config;

import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;

/**
 * Handler que se ejecuta automáticamente después de que SAML2 autentica exitosamente.
 * 
 * Este componente se engacha en la cadena de seguridad estándar (Saml2WebSsoAuthenticationFilter)
 * y NO expone ningún endpoint.
 * 
 * Su propósito: almacenar datos de SAML en sesión para que la lógica de autorización
 * de Spring OAuth2 pueda usarlos.
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

        if (authentication instanceof Saml2Authentication) {
            Saml2Authentication samlAuth = (Saml2Authentication) authentication;
            HttpSession session = request.getSession();

            // Guardar datos de SAML en sesión para acceso posterior
            String nameId = samlAuth.getName();
            session.setAttribute("saml_user_id", nameId);
            session.setAttribute("saml_authenticated", true);

            System.out.println("[SAML_SUCCESS] User authenticated: " + nameId);
        }

        // Delegar al handler estándar para redirigir correctamente
        super.onAuthenticationSuccess(request, response, authentication);
    }
}
