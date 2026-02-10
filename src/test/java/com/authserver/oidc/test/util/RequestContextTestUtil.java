package com.authserver.oidc.test.util;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Base64;

/**
 * Test utility for managing RequestContextHolder and MockHttpServletRequest.
 * Used to simulate HTTP request context in tests, enabling extraction of client_id and redirect_uri.
 */
public class RequestContextTestUtil {

    private static final ThreadLocal<ServletRequestAttributes> CONTEXT = new ThreadLocal<>();

    /**
     * Sets up RequestContextHolder with a mock request containing client_id and redirect_uri parameters.
     *
     * @param clientId     OAuth2 client identifier
     * @param redirectUri  OAuth2 redirect URI
     */
    public static void setupRequestContext(String clientId, String redirectUri) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("POST");
        request.setRequestURI("/oauth2/token");
        request.addParameter("client_id", clientId);
        request.addParameter("redirect_uri", redirectUri);
        request.addParameter("grant_type", "authorization_code");

        ServletRequestAttributes attrs = new ServletRequestAttributes(request);
        CONTEXT.set(attrs);
        RequestContextHolder.setRequestAttributes(attrs);
    }

    /**
     * Sets up RequestContextHolder with a mock request containing Authorization Basic header.
     * This simulates client authentication via HTTP Basic (client_id:client_secret).
     *
     * @param clientId      OAuth2 client identifier
     * @param clientSecret  OAuth2 client secret
     * @param redirectUri   OAuth2 redirect URI
     */
    public static void setupRequestContextWithBasicAuth(String clientId, String clientSecret, String redirectUri) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("POST");
        request.setRequestURI("/oauth2/token");
        
        // Set Authorization header (Basic client_id:client_secret)
        String credentials = clientId + ":" + clientSecret;
        String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());
        request.addHeader("Authorization", "Basic " + encodedCredentials);
        
        request.addParameter("redirect_uri", redirectUri);
        request.addParameter("grant_type", "authorization_code");

        ServletRequestAttributes attrs = new ServletRequestAttributes(request);
        CONTEXT.set(attrs);
        RequestContextHolder.setRequestAttributes(attrs);
    }

    /**
     * Sets up RequestContextHolder with a mock request containing MISMATCHED client_id.
     * Used to test binding validation failure scenarios.
     *
     * @param wrongClientId  Incorrect client identifier (not the one used during authorization)
     * @param redirectUri    OAuth2 redirect URI
     */
    public static void setupRequestContextWithWrongClient(String wrongClientId, String redirectUri) {
        setupRequestContext(wrongClientId, redirectUri);
    }

    /**
     * Sets up RequestContextHolder with a mock request containing MISMATCHED redirect_uri.
     * Used to test binding validation failure scenarios.
     *
     * @param clientId         OAuth2 client identifier
     * @param wrongRedirectUri Incorrect redirect URI (not the one used during authorization)
     */
    public static void setupRequestContextWithWrongRedirect(String clientId, String wrongRedirectUri) {
        setupRequestContext(clientId, wrongRedirectUri);
    }

    /**
     * Clears RequestContextHolder after test execution.
     * MUST be called in @AfterEach to prevent context leakage between tests.
     */
    public static void clearRequestContext() {
        RequestContextHolder.resetRequestAttributes();
        CONTEXT.remove();
    }
}
