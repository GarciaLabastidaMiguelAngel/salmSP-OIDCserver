package com.authserver.oidc.test.technical.saml;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Technical test for SAML2 configuration.
 * 
 * Validates that Spring Security SAML2 SP beans are correctly configured.
 */
@SpringBootTest
class SamlAuthenticateEndpointTechnicalTest {

    @Autowired
    private RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

    @Test
    void saml_relying_party_registration_configured() throws Exception {
        // WHEN: Verify SAML2 SP configuration is loaded
        // THEN: RelyingPartyRegistrationRepository bean should be available and configured
        assertThat(relyingPartyRegistrationRepository)
            .as("RelyingPartyRegistrationRepository should be configured")
            .isNotNull();
        
        // Verify the 'bet' registration exists
        var betRegistration = relyingPartyRegistrationRepository.findByRegistrationId("bet");
        assertThat(betRegistration)
            .as("SAML2 registration 'bet' should exist")
            .isNotNull();
    }
}

