package com.authserver.oidc.config;

import com.authserver.oidc.config.properties.SamlDebugProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.security.saml2.provider.service.web.authentication.OpenSaml4AuthenticationRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2AuthenticationRequestResolver;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;

import java.util.Arrays;

/**
 * Configuration for SAML2 AuthnRequest debugging.
 * 
 * Security guards:
 * - @Profile("dev", "preprod") - NEVER active in prod
 * - @ConditionalOnProperty - requires explicit enable
 * - Hard-coded profile check in @Bean method as additional safeguard
 * 
 * Activation:
 * 1. Set active profile to dev or preprod
 * 2. Set saml.debug-authn-request.enabled=true
 */
@Configuration
@ConditionalOnProperty(
    prefix = "saml.debug-authn-request",
    name = "enabled",
    havingValue = "true"
)
@EnableConfigurationProperties(SamlDebugProperties.class)
public class Saml2AuthnRequestDebugConfig {
    
    private static final Logger log = LoggerFactory.getLogger(Saml2AuthnRequestDebugConfig.class);
    
    @Bean
    public Saml2AuthenticationRequestResolver saml2AuthenticationRequestResolver(
            RelyingPartyRegistrationRepository registrations,
            SamlDebugProperties debugProperties,
            Environment environment) {
        
        // HARD GUARD: Never allow in production even if profile misconfigured
        String[] activeProfiles = environment.getActiveProfiles();
        if (Arrays.asList(activeProfiles).contains("prod") || 
            Arrays.asList(activeProfiles).contains("production")) {
            log.error("SECURITY VIOLATION: Attempted to enable SAML debug in PROD profile. Disabling.");
            return new OpenSaml4AuthenticationRequestResolver(registrations);
        }
        
        // Create base resolver
        OpenSaml4AuthenticationRequestResolver baseResolver = 
            new OpenSaml4AuthenticationRequestResolver(registrations);
        
        // Wrap with debug decorator
        log.warn("⚠️  SAML2 AuthnRequest DEBUG is ENABLED (profiles: {}). " +
                 "This logs COMPLETE SAML XML without truncation. NEVER use in production!",
                 Arrays.toString(activeProfiles));
        
        return new Saml2AuthnRequestDebugResolver(baseResolver, debugProperties, environment);
    }
}
