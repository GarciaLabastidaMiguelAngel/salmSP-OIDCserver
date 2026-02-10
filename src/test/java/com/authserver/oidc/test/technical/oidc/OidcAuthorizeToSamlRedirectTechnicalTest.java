package com.authserver.oidc.test.technical.oidc;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * BLACK-BOX HTTP test for OIDC authorize endpoint redirecting to SAML authenticate.
 * 
 * Validates only observable HTTP behavior:
 * - 302 redirect from /oauth2/authorize to /saml2/authenticate/bet
 * - Session cookie is set (SESSION= or JSESSIONID=)
 * - Does NOT redirect to client's redirect_uri
 * 
 * Does NOT inspect internal state (session, security context, saved request).
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class OidcAuthorizeToSamlRedirectTechnicalTest {

    @Autowired
    private MockMvc mockMvc;

    private static final String REGISTRATION_ID = "bet";

    @Test
    void http_oidc_authorize_unauthenticated_redirects_to_saml_authenticate_and_sets_cookie() throws Exception {
        // GIVEN: OIDC authorize endpoint with complete happy path parameters
        Map<String, String> oidcParams = buildOidcAuthorizeParams();
        
        String authorizeUrl = "/oauth2/authorize" + toQueryString(oidcParams);

        // WHEN: GET request (unauthenticated user initiates OIDC flow)
        MvcResult result = mockMvc.perform(get(authorizeUrl))
            .andExpect(status().isFound()) // 302
            .andReturn();

        // THEN: Validate redirect to SAML authenticate endpoint
        String location = extractLocation(result);
        assertThat(location)
            .as("Location header must redirect to SAML authenticate endpoint")
            .isNotNull()
            .contains("/saml2/authenticate/" + REGISTRATION_ID);

        // THEN: Validate Location does NOT redirect to client's redirect_uri
        assertThat(location)
            .as("Location should not redirect to client callback yet")
            .doesNotContain("localhost:8081")
            .doesNotContain("code=");

        // THEN: Validate session cookie is explicitly set in Set-Cookie header (BLACK-BOX HTTP validation)
        var setCookieHeaders = result.getResponse().getHeaders("Set-Cookie");
        
        assertThat(setCookieHeaders)
            .as("Set-Cookie headers should contain session cookie from /oauth2/authorize. " +
                "Status: %s, Location: %s, Set-Cookie headers: %s", 
                result.getResponse().getStatus(), 
                location,
                setCookieHeaders)
            .isNotEmpty();

        // Find session cookie (JSESSIONID or SESSION)
        String sessionCookie = setCookieHeaders.stream()
            .filter(cookie -> cookie.startsWith("JSESSIONID=") || cookie.startsWith("SESSION="))
            .findFirst()
            .orElse(null);

        assertThat(sessionCookie)
            .as("Session cookie (JSESSIONID= or SESSION=) must be present in Set-Cookie headers. " +
                "Available Set-Cookie: %s", setCookieHeaders)
            .isNotNull();

        assertThat(sessionCookie)
            .as("Session cookie must contain Path=/ attribute")
            .contains("Path=/");

        assertThat(sessionCookie)
            .as("Session cookie should contain HttpOnly attribute for security")
            .containsIgnoringCase("HttpOnly");

        // Extract session value (before first ';') to validate format
        int semicolonIdx = sessionCookie.indexOf(';');
        String sessionValue = semicolonIdx > 0 ? sessionCookie.substring(0, semicolonIdx) : sessionCookie;
        
        assertThat(sessionValue)
            .as("Session cookie value must have valid format with sufficient length")
            .matches("^(JSESSIONID|SESSION)=.{10,}"); // At least 10 chars after '='
    }

    /**
     * Builds complete OIDC authorize parameters for happy path.
     * Returns query string (not map) to preserve parameter order.
     */
    private Map<String, String> buildOidcAuthorizeParams() {
        Map<String, String> params = new HashMap<>();
        params.put("client_id", "example-client");
        params.put("response_type", "code");
        params.put("redirect_uri", "http://localhost:8081/callback");
        params.put("scope", "openid");
        params.put("state", "test-state");
        params.put("nonce", "test-nonce");
        params.put("code_challenge", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
        params.put("code_challenge_method", "S256");
        return params;
    }

    /**
     * Converts parameter map to query string.
     * Uses specific order: client_id first (required by Spring Authorization Server).
     */
    private String toQueryString(Map<String, String> params) {
        StringBuilder sb = new StringBuilder("?");
        // client_id MUST be first
        sb.append("client_id=").append(params.get("client_id"));
        params.forEach((key, value) -> {
            if (!key.equals("client_id")) {
                sb.append("&").append(key).append("=").append(value);
            }
        });
        return sb.toString();
    }

    /**
     * Extracts Location header from MvcResult.
     */
    private String extractLocation(MvcResult result) {
        return result.getResponse().getHeader("Location");
    }

    /**
     * Extracts session cookie (SESSION= or JSESSIONID=) from Set-Cookie headers.
     * Returns only the cookie name=value pair (without attributes like Path, HttpOnly).
     */
    private String extractSessionCookie(MvcResult result) {
        var setCookieHeaders = result.getResponse().getHeaders("Set-Cookie");
        
        for (String cookieHeader : setCookieHeaders) {
            if (cookieHeader.startsWith("SESSION=") || cookieHeader.startsWith("JSESSIONID=")) {
                // Extract only "SESSION=value" or "JSESSIONID=value" (before first ';')
                int semicolonIdx = cookieHeader.indexOf(';');
                if (semicolonIdx > 0) {
                    return cookieHeader.substring(0, semicolonIdx);
                }
                return cookieHeader;
            }
        }
        
        return null;
    }

    /**
     * Extracts path from URL using java.net.URI.
     */
    private String locationPath(String url) {
        try {
            URI uri = new URI(url);
            return uri.getPath();
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse URL path: " + url, e);
        }
    }

    /**
     * Extracts query parameters from URL without external libraries.
     */
    private Map<String, String> extractQueryParams(String url) {
        Map<String, String> params = new HashMap<>();
        try {
            URI uri = new URI(url);
            String query = uri.getQuery();
            if (query != null && !query.isEmpty()) {
                String[] pairs = query.split("&");
                for (String pair : pairs) {
                    int idx = pair.indexOf("=");
                    if (idx > 0) {
                        String key = pair.substring(0, idx);
                        String value = pair.substring(idx + 1);
                        params.put(key, value);
                    }
                }
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse URL query params: " + url, e);
        }
        return params;
    }
}
