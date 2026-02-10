package com.authserver.oidc.config;

import com.authserver.oidc.logout.Saml2LogoutSuccessHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2AuthenticationRequestResolver;
import org.springframework.security.web.SecurityFilterChain;

import com.authserver.oidc.config.properties.SamlProperties;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;

/**
 * Configuración de seguridad para SAML2 SP.
 * 
 * Flujo integrado (sin controladores):
 * 1. GET /oauth2/authorize → usuario no autenticado → redirige a /saml2/authenticate/{registrationId}
 * 2. SAML2 autentica con IdP
 * 3. Saml2SuccessHandler se ejecuta automáticamente (sin endpoint extra)
 * 4. Redirige a /oauth2/authorize con credenciales SAML
 * 5. Spring Authorization Server genera authorization code
 */
@Configuration
@EnableConfigurationProperties(SamlProperties.class)
@ConditionalOnProperty(name = "saml.enabled", havingValue = "true", matchIfMissing = true)
public class SecurityConfig {

    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    @Autowired(required = false)
    private Saml2SuccessHandler saml2SuccessHandler;
    
    @Autowired(required = false)
    @Lazy
    private Saml2AuthenticationRequestResolver customAuthenticationRequestResolver;
    
    @Autowired
    private Saml2LogoutSuccessHandler saml2LogoutSuccessHandler;

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                // SAML endpoints only (OAuth2 endpoints handled by @Order(1) filter chain)
                .requestMatchers("/error").permitAll()
                .requestMatchers("/saml2/**").permitAll()
                // All other requests require authentication
                .anyRequest().authenticated()
            )
            .saml2Login(saml2 -> {
                if (saml2SuccessHandler != null) {
                    saml2.successHandler(saml2SuccessHandler);
                }
                if (customAuthenticationRequestResolver != null) {
                    saml2.authenticationRequestResolver(customAuthenticationRequestResolver);
                    log.info("Using custom SAML2 AuthenticationRequestResolver (debug enabled)");
                }
            })
            .logout(logout -> logout
                .logoutSuccessHandler(saml2LogoutSuccessHandler)
            )
            .saml2Logout(Customizer.withDefaults())
            .saml2Metadata(Customizer.withDefaults());
        
        return http.build();
    }


    @Bean
    public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository(
            SamlProperties samlProperties, 
            ResourceLoader resourceLoader) {
        
        try {
            // Load SAML keystore
            Resource keystoreResource = resourceLoader.getResource(samlProperties.getKeystore().getLocation());
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            
            try (InputStream is = keystoreResource.getInputStream()) {
                keyStore.load(is, samlProperties.getKeystore().getPassword().toCharArray());
            }
            
            // Get SP signing key
            RSAPrivateKey privateKey = (RSAPrivateKey) keyStore.getKey(
                samlProperties.getKeystore().getAlias(),
                samlProperties.getKeystore().getKeyPassword().toCharArray()
            );
            X509Certificate spCertificate = (X509Certificate) keyStore.getCertificate(
                samlProperties.getKeystore().getAlias()
            );
            
            // Get IdP verification certificate from PEM file
            X509Certificate idpCertificate;
            String certLocation = samlProperties.getIdp().getVerificationCertLocation();
            
            if (certLocation != null && !certLocation.isEmpty()) {
                // Load from PEM file
                Resource certResource = resourceLoader.getResource(certLocation);
                try (InputStream certStream = certResource.getInputStream()) {
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    idpCertificate = (X509Certificate) cf.generateCertificate(certStream);
                }
            } else {
                // Fallback: Load from keystore (legacy)
                Certificate idpCert = keyStore.getCertificate(samlProperties.getIdp().getVerificationCertAlias());
                if (idpCert == null) {
                    throw new RuntimeException("IdP verification certificate not found");
                }
                idpCertificate = (X509Certificate) idpCert;
            }
            
            // Get SP configuration
            SamlProperties.Sp spConfig = samlProperties.getSp();
            
            // Validate required external base URL
            if (spConfig.getExternalBaseUrl() == null || spConfig.getExternalBaseUrl().isBlank()) {
                throw new RuntimeException(
                    "SAML SP configuration error: saml.sp.external-base-url is required (e.g., https://login.example.com). " +
                    "Do not use placeholders like {baseUrl} in Kubernetes/Ingress deployments."
                );
            }
            
            // Construct SP URLs using external base URL
            String spEntityId = spConfig.getResolvedEntityId();
            String acsUrl = spConfig.getExternalBaseUrl() + spConfig.buildUrl(spConfig.getAcsPath());
            String sloRequestUrl = spConfig.getExternalBaseUrl() + spConfig.getSloRequestPath();
            String sloResponseUrl = spConfig.getExternalBaseUrl() + spConfig.getSloResponsePath();
            
            // Parse binding preferences (case-insensitive)
            Saml2MessageBinding acsBinding = "REDIRECT".equalsIgnoreCase(spConfig.getAcsBinding()) 
                ? Saml2MessageBinding.REDIRECT 
                : Saml2MessageBinding.POST;
            Saml2MessageBinding ssoBinding = "REDIRECT".equalsIgnoreCase(spConfig.getSsoBinding()) 
                ? Saml2MessageBinding.REDIRECT 
                : Saml2MessageBinding.POST;
            
            // Build RelyingPartyRegistration with AuthnRequest signing enabled
            RelyingPartyRegistration registration = RelyingPartyRegistration
                .withRegistrationId(spConfig.getRegistrationId())
                .entityId(spEntityId)
                .assertionConsumerServiceLocation(acsUrl)
                .assertionConsumerServiceBinding(acsBinding)
                .singleLogoutServiceLocation(sloRequestUrl)
                .singleLogoutServiceResponseLocation(sloResponseUrl)
                .singleLogoutServiceBinding(Saml2MessageBinding.POST)
                // SP signing credential for AuthnRequest signature
                .signingX509Credentials(c -> c.add(
                    org.springframework.security.saml2.core.Saml2X509Credential.signing(privateKey, spCertificate)
                ))
                .assertingPartyDetails(party -> party
                    .entityId(samlProperties.getIdp().getEntityId())
                    .singleSignOnServiceLocation(samlProperties.getIdp().getSsoUrl())
                    .singleSignOnServiceBinding(ssoBinding)
                    // IdP verification credential for Response/Assertion signature verification
                    .verificationX509Credentials(c -> c.add(
                        org.springframework.security.saml2.core.Saml2X509Credential.verification(idpCertificate)
                    ))
                    // Request IdP to expect signed AuthnRequest
                    .wantAuthnRequestsSigned(true)
                )
                .build();
            
            log.info("╔════════════════════════════════════════════════════════════════╗");
            log.info("║            SAML2 SP Configuration - External URLs               ║");
            log.info("╠════════════════════════════════════════════════════════════════╣");
            log.info("║ Registration ID          : {}", String.format("%-35s ║", spConfig.getRegistrationId()));
            log.info("║ External Base URL        : {}", String.format("%-35s ║", spConfig.getExternalBaseUrl()));
            log.info("║ SP Entity ID             : {}", String.format("%-35s ║", spEntityId));
            log.info("║ Metadata URL             : {}", String.format("%-35s ║", spConfig.getExternalBaseUrl() + spConfig.buildUrl(spConfig.getMetadataPath())));
            log.info("║ ACS URL                  : {}", String.format("%-35s ║", acsUrl));
            log.info("║ ACS Binding              : {}", String.format("%-35s ║", spConfig.getAcsBinding()));
            log.info("║ SLO Request URL          : {}", String.format("%-35s ║", sloRequestUrl));
            log.info("║ SLO Response URL         : {}", String.format("%-35s ║", sloResponseUrl));
            log.info("║ IdP Entity ID            : {}", String.format("%-35s ║", samlProperties.getIdp().getEntityId()));
            log.info("║ IdP SSO URL              : {}", String.format("%-35s ║", samlProperties.getIdp().getSsoUrl()));
            log.info("║ IdP SSO Binding          : {}", String.format("%-35s ║", spConfig.getSsoBinding()));
            log.info("║ SP AuthnRequest Signing  : ENABLED                             ║");
            log.info("║ SP Certificate Subject   : {}", String.format("%-35s ║", truncate(spCertificate.getSubjectX500Principal().toString(), 35)));
            log.info("╚════════════════════════════════════════════════════════════════╝");
            
            return new InMemoryRelyingPartyRegistrationRepository(registration);
            
        } catch (RuntimeException e) {
            log.error("❌ SAML2 SP configuration FAILED: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("❌ Failed to configure SAML2 SP: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to configure SAML2 SP", e);
        }
    }
    
    private String truncate(String s, int maxLen) {
        if (s == null) return "";
        return s.length() > maxLen ? s.substring(0, maxLen) : s;
    }
}
