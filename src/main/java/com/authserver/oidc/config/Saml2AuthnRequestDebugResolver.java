package com.authserver.oidc.config;

import com.authserver.oidc.config.properties.SamlDebugProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2AuthenticationRequestResolver;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.zip.Inflater;

/**
 * Decorator for Saml2AuthenticationRequestResolver that logs AuthnRequest XML.
 * 
 * Security constraints:
 * - Only active in dev/preprod profiles (checked at bean registration)
 * - Controlled by saml.debug-authn-request.enabled property
 * - Never creates endpoints or exposes data externally
 * - Uses SLF4J logger (not System.out)
 */
public class Saml2AuthnRequestDebugResolver implements Saml2AuthenticationRequestResolver {
    
    private static final Logger log = LoggerFactory.getLogger(Saml2AuthnRequestDebugResolver.class);
    
    private final Saml2AuthenticationRequestResolver delegate;
    private final SamlDebugProperties debugProperties;
    private final Environment environment;
    
    public Saml2AuthnRequestDebugResolver(
            Saml2AuthenticationRequestResolver delegate,
            SamlDebugProperties debugProperties,
            Environment environment) {
        this.delegate = delegate;
        this.debugProperties = debugProperties;
        this.environment = environment;
    }
    
    @Override
    public <T extends AbstractSaml2AuthenticationRequest> T resolve(HttpServletRequest request) {
        T authRequest = delegate.resolve(request);
        
        if (authRequest != null && debugProperties.isEnabled()) {
            logAuthRequest(authRequest);
        }
        
        return authRequest;
    }
    
    private void logAuthRequest(AbstractSaml2AuthenticationRequest authRequest) {
        try {
            String samlRequestBase64 = authRequest.getSamlRequest();
            String registrationId = authRequest.getRelyingPartyRegistrationId();
            String authRequestUri = authRequest.getAuthenticationRequestUri();
            String relayState = authRequest.getRelayState();
            
            String xml = decodeToXml(samlRequestBase64);
            String[] activeProfiles = environment.getActiveProfiles();
            
            if (xml != null) {
                // Extract metadata from XML
                String requestId = extractValue(xml, "ID=\"", "\"");
                String issueInstant = extractValue(xml, "IssueInstant=\"", "\"");
                String issuer = extractValue(xml, "<saml2:Issuer>", "</saml2:Issuer>");
                if (issuer == null) {
                    issuer = extractValue(xml, "<saml:Issuer>", "</saml:Issuer>");
                }
                String acsUrl = extractValue(xml, "AssertionConsumerServiceURL=\"", "\"");
                String destination = extractValue(xml, "Destination=\"", "\"");
                
                // Detect binding
                String binding = "POST"; // Default assumption for this implementation
                if (xml.contains("ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"")) {
                    binding = "POST";
                } else if (xml.contains("ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\"")) {
                    binding = "REDIRECT";
                }
                
                // Detect if signature expected/present
                boolean hasSigElement = xml.contains("<ds:Signature") || xml.contains("<Signature");
                boolean wantsSignedRequests = xml.contains("AuthnRequestsSigned=\"true\"");
                
                // Format XML if pretty-print enabled
                String displayXml = xml;
                if (debugProperties.isPrettyPrint()) {
                    displayXml = prettyPrintXml(xml);
                }
                
                log.info("\n" +
                    "═══════════════════════════════════════════════════════════════════════════════\n" +
                    "  SAML2 AuthnRequest DEBUG (dev/preprod only) - COMPLETE OUTPUT\n" +
                    "═══════════════════════════════════════════════════════════════════════════════\n" +
                    "Active Profiles       : {}\n" +
                    "Debug Enabled         : {}\n" +
                    "Pretty Print          : {}\n" +
                    "───────────────────────────────────────────────────────────────────────────────\n" +
                    "REQUEST METADATA:\n" +
                    "  Registration ID     : {}\n" +
                    "  Binding             : {}\n" +
                    "  Request ID          : {}\n" +
                    "  IssueInstant        : {}\n" +
                    "  SP Issuer/EntityID  : {}\n" +
                    "  ACS URL             : {}\n" +
                    "  IdP Destination/SSO : {}\n" +
                    "  Relay State         : {}\n" +
                    "───────────────────────────────────────────────────────────────────────────────\n" +
                    "SIGNATURE INFO:\n" +
                    "  Has <ds:Signature>  : {}\n" +
                    "  Signature Status    : {}\n" +
                    "───────────────────────────────────────────────────────────────────────────────\n" +
                    "AuthnRequest XML (COMPLETE - {} chars):\n" +
                    "───────────────────────────────────────────────────────────────────────────────\n" +
                    "{}\n" +
                    "───────────────────────────────────────────────────────────────────────────────\n" +
                    "Base64 SAMLRequest (COMPLETE - {} chars - Copy/Paste Ready):\n" +
                    "───────────────────────────────────────────────────────────────────────────────\n" +
                    "{}\n" +
                    "───────────────────────────────────────────────────────────────────────────────\n" +
                    "RelayState (Copy/Paste Ready):\n" +
                    "───────────────────────────────────────────────────────────────────────────────\n" +
                    "{}\n" +
                    "═══════════════════════════════════════════════════════════════════════════════",
                    Arrays.toString(activeProfiles),
                    debugProperties.isEnabled(),
                    debugProperties.isPrettyPrint(),
                    registrationId,
                    binding,
                    requestId != null ? requestId : "(not found)",
                    issueInstant != null ? issueInstant : "(not found)",
                    issuer != null ? issuer : "(not found)",
                    acsUrl != null ? acsUrl : "(not found)",
                    destination != null ? destination : authRequestUri,
                    relayState != null ? relayState : "(none)",
                    hasSigElement,
                    hasSigElement ? "✅ SIGNED (embedded <ds:Signature> for POST binding)" : "⚠️  NOT SIGNED",
                    displayXml.length(),
                    displayXml,
                    samlRequestBase64.length(),
                    samlRequestBase64,
                    relayState != null ? relayState : "(none)"
                );
                
            } else {
                log.warn("Could not decode SAMLRequest to XML. Base64 length: {}", samlRequestBase64.length());
            }
            
        } catch (Exception e) {
            log.error("Error logging AuthnRequest", e);
        }
    }
    
    /**
     * Extract value between delimiters from XML string.
     */
    private String extractValue(String xml, String startDelim, String endDelim) {
        try {
            int start = xml.indexOf(startDelim);
            if (start == -1) return null;
            start += startDelim.length();
            int end = xml.indexOf(endDelim, start);
            if (end == -1) return null;
            return xml.substring(start, end);
        } catch (Exception e) {
            return null;
        }
    }
    
    /**
     * Simple XML pretty-print (basic indentation).
     */
    private String prettyPrintXml(String xml) {
        try {
            // Basic indentation logic
            String result = xml.replaceAll(">\\s*<", ">\n<");
            String[] lines = result.split("\n");
            StringBuilder formatted = new StringBuilder();
            int indent = 0;
            
            for (String line : lines) {
                line = line.trim();
                if (line.isEmpty()) continue;
                
                // Decrease indent for closing tags
                if (line.startsWith("</")) {
                    indent = Math.max(0, indent - 2);
                }
                
                // Add indentation
                formatted.append("  ".repeat(Math.max(0, indent / 2)));
                formatted.append(line);
                formatted.append("\n");
                
                // Increase indent for opening tags (but not self-closing)
                if (line.startsWith("<") && !line.startsWith("</") && 
                    !line.endsWith("/>") && !line.contains("</")) {
                    indent += 2;
                }
            }
            
            return formatted.toString();
        } catch (Exception e) {
            // Fallback to original if pretty-print fails
            return xml;
        }
    }
    
    /**
     * Robust decoder for SAMLRequest Base64 string without size limitations.
     * Handles both POST binding (Base64 → UTF-8 XML) and REDIRECT binding (Base64 → Deflate → UTF-8).
     * Uses ByteArrayOutputStream for dynamic sizing without truncation.
     */
    private String decodeToXml(String samlRequestBase64) {
        try {
            byte[] decoded = Base64.getDecoder().decode(samlRequestBase64);
            
            // Try direct UTF-8 decode (POST binding typically)
            String directXml = new String(decoded, StandardCharsets.UTF_8);
            if (isValidXml(directXml)) {
                return directXml;
            }
            
            // Try DEFLATE decompression (REDIRECT binding) - no size limits
            try {
                Inflater inflater = new Inflater(true); // raw DEFLATE
                inflater.setInput(decoded);
                
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                byte[] buffer = new byte[4096];
                
                while (!inflater.finished()) {
                    int count = inflater.inflate(buffer);
                    if (count == 0) {
                        break;
                    }
                    outputStream.write(buffer, 0, count);
                }
                
                inflater.end();
                
                String inflatedXml = outputStream.toString(StandardCharsets.UTF_8);
                if (isValidXml(inflatedXml)) {
                    return inflatedXml;
                }
            } catch (Exception inflateEx) {
                // Not deflated, continue with direct decode
                log.debug("DEFLATE decompression failed, using direct decode", inflateEx);
            }
            
            // Fallback: return direct decode even if not perfect XML
            return directXml;
            
        } catch (Exception e) {
            log.error("Failed to decode SAMLRequest", e);
            return null;
        }
    }
    
    private boolean isValidXml(String str) {
        return str != null && 
               str.trim().startsWith("<") && 
               (str.contains("AuthnRequest") || str.contains("saml"));
    }
}
