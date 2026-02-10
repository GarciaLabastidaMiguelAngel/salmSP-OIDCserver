package com.authserver.oidc.test.util;

import org.springframework.core.io.ClassPathResource;

import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Base64;

/**
 * Utility class to generate static SAML2 Service Provider metadata XML.
 * This generates the metadata WITHOUT exposing it as an HTTP endpoint.
 * 
 * Usage:
 * 1. Run this class as a Java application (main method)
 * 2. Copy the generated XML from console or file
 * 3. Upload to SAMLtest.id or your IdP
 * 
 * To regenerate after keystore changes:
 * - Update keystore file: src/main/resources/keystore/saml-keystore.p12
 * - Run this class again
 * - Replace the XML file: src/main/resources/saml/sp-metadata-bet.xml
 */
public class SamlMetadataGenerator {

    // Configuration - must match application.yml
    private static final String KEYSTORE_PATH = "keystore/saml-keystore.p12";
    private static final String KEYSTORE_PASSWORD = "changeit";
    private static final String SP_KEY_ALIAS = "saml";
    private static final String KEY_PASSWORD = "changeit";
    
    // SP Configuration
    private static final String REGISTRATION_ID = "bet";
    private static final String BASE_URL = "http://localhost:8080";
    private static final String SP_ENTITY_ID = BASE_URL + "/saml2/service-provider-metadata/" + REGISTRATION_ID;
    private static final String ACS_URL = BASE_URL + "/login/saml2/sso/" + REGISTRATION_ID;
    private static final String SLO_URL = BASE_URL + "/logout/saml2/slo";
    
    public static void main(String[] args) throws Exception {
        String metadata = generateMetadataXml();
        
        System.out.println("=".repeat(80));
        System.out.println("SAML2 Service Provider Metadata (registrationId: " + REGISTRATION_ID + ")");
        System.out.println("=".repeat(80));
        System.out.println(metadata);
        System.out.println("=".repeat(80));
        
        // Optionally save to file
        String outputPath = "src/main/resources/saml/sp-metadata-bet.xml";
        try (FileOutputStream fos = new FileOutputStream(outputPath)) {
            fos.write(metadata.getBytes());
            System.out.println("\n✅ Metadata saved to: " + outputPath);
        } catch (Exception e) {
            System.out.println("\n⚠️ Could not save to file (this is OK, copy from console): " + e.getMessage());
        }
    }
    
    /**
     * Generates SAML2 SP metadata XML from keystore.
     */
    public static String generateMetadataXml() throws Exception {
        // Load keystore
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        ClassPathResource resource = new ClassPathResource(KEYSTORE_PATH);
        
        try (InputStream is = resource.getInputStream()) {
            keyStore.load(is, KEYSTORE_PASSWORD.toCharArray());
        }
        
        // Extract certificate
        X509Certificate cert = (X509Certificate) keyStore.getCertificate(SP_KEY_ALIAS);
        if (cert == null) {
            throw new RuntimeException("Certificate not found for alias: " + SP_KEY_ALIAS);
        }
        
        // Encode certificate in Base64
        String certBase64 = Base64.getEncoder().encodeToString(cert.getEncoded());
        
        // Generate metadata XML
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"" + SP_ENTITY_ID + "\">\n" +
            "  <SPSSODescriptor AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n" +
            "    <KeyDescriptor use=\"signing\">\n" +
            "      <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
            "        <X509Data>\n" +
            "          <X509Certificate>" + certBase64 + "</X509Certificate>\n" +
            "        </X509Data>\n" +
            "      </KeyInfo>\n" +
            "    </KeyDescriptor>\n" +
            "    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>\n" +
            "    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"" + ACS_URL + "\" index=\"0\" isDefault=\"true\"/>\n" +
            "    <SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"" + SLO_URL + "\"/>\n" +
            "  </SPSSODescriptor>\n" +
            "</EntityDescriptor>";
    }
}
