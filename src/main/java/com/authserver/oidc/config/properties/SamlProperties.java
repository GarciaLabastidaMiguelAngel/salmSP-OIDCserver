package com.authserver.oidc.config.properties;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties(prefix = "saml")
@Validated
public class SamlProperties {

    private Keystore keystore = new Keystore();
    private Idp idp = new Idp();
    private Sp sp = new Sp();

    public Keystore getKeystore() {
        return keystore;
    }

    public void setKeystore(Keystore keystore) {
        this.keystore = keystore;
    }

    public Idp getIdp() {
        return idp;
    }

    public void setIdp(Idp idp) {
        this.idp = idp;
    }

    public Sp getSp() {
        return sp;
    }

    public void setSp(Sp sp) {
        this.sp = sp;
    }

    public static class Keystore {
        @NotBlank
        private String location;
        @NotBlank
        private String password;
        @NotBlank
        private String alias;
        @NotBlank
        private String keyPassword;

        public String getLocation() {
            return location;
        }

        public void setLocation(String location) {
            this.location = location;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }

        public String getAlias() {
            return alias;
        }

        public void setAlias(String alias) {
            this.alias = alias;
        }

        public String getKeyPassword() {
            return keyPassword;
        }

        public void setKeyPassword(String keyPassword) {
            this.keyPassword = keyPassword;
        }
    }

    public static class Idp {
        @NotBlank
        private String entityId;
        @NotBlank
        private String ssoUrl;
        
        // Support both cert from keystore (legacy) or PEM file
        private String verificationCertAlias;
        private String verificationCertLocation;

        public String getEntityId() {
            return entityId;
        }

        public void setEntityId(String entityId) {
            this.entityId = entityId;
        }

        public String getSsoUrl() {
            return ssoUrl;
        }

        public void setSsoUrl(String ssoUrl) {
            this.ssoUrl = ssoUrl;
        }

        public String getVerificationCertAlias() {
            return verificationCertAlias;
        }

        public void setVerificationCertAlias(String verificationCertAlias) {
            this.verificationCertAlias = verificationCertAlias;
        }

        public String getVerificationCertLocation() {
            return verificationCertLocation;
        }

        public void setVerificationCertLocation(String verificationCertLocation) {
            this.verificationCertLocation = verificationCertLocation;
        }
    }

    /**
     * Service Provider (SP) configuration for SAML.
     * Uses external base URL for Kubernetes/Ingress deployments.
     */
    public static class Sp {
        @NotBlank(message = "saml.sp.external-base-url is required (e.g., https://login.example.com)")
        private String externalBaseUrl;

        private String registrationId = "bet";
        private String entityId; // Optional; defaults to externalBaseUrl + metadataPath
        
        private String metadataPath = "/saml2/service-provider-metadata/{registrationId}";
        private String acsPath = "/login/saml2/sso/{registrationId}";
        private String sloRequestPath = "/logout/saml2/slo";
        private String sloResponsePath = "/logout/saml2/slo";
        
        private String acsBinding = "POST";  // POST or REDIRECT
        private String ssoBinding = "POST";  // POST or REDIRECT

        public String getExternalBaseUrl() {
            return externalBaseUrl;
        }

        public void setExternalBaseUrl(String externalBaseUrl) {
            this.externalBaseUrl = externalBaseUrl;
        }

        public String getRegistrationId() {
            return registrationId;
        }

        public void setRegistrationId(String registrationId) {
            this.registrationId = registrationId;
        }

        public String getEntityId() {
            return entityId;
        }

        public void setEntityId(String entityId) {
            this.entityId = entityId;
        }

        public String getMetadataPath() {
            return metadataPath;
        }

        public void setMetadataPath(String metadataPath) {
            this.metadataPath = metadataPath;
        }

        public String getAcsPath() {
            return acsPath;
        }

        public void setAcsPath(String acsPath) {
            this.acsPath = acsPath;
        }

        public String getSloRequestPath() {
            return sloRequestPath;
        }

        public void setSloRequestPath(String sloRequestPath) {
            this.sloRequestPath = sloRequestPath;
        }

        public String getSloResponsePath() {
            return sloResponsePath;
        }

        public void setSloResponsePath(String sloResponsePath) {
            this.sloResponsePath = sloResponsePath;
        }

        public String getAcsBinding() {
            return acsBinding;
        }

        public void setAcsBinding(String acsBinding) {
            this.acsBinding = acsBinding;
        }

        public String getSsoBinding() {
            return ssoBinding;
        }

        public void setSsoBinding(String ssoBinding) {
            this.ssoBinding = ssoBinding;
        }

        /**
         * Construye la URL completa resolviendo placeholders.
         */
        public String buildUrl(String template) {
            if (template == null) {
                return null;
            }
            return template
                .replace("{registrationId}", registrationId);
        }

        /**
         * Construye el Entity ID si no fue provisto explícitamente.
         */
        public String getResolvedEntityId() {
            if (entityId != null && !entityId.isBlank()) {
                return entityId;
            }
            // Default: externalBaseUrl + metadataPath
            String metadataUrl = buildUrl(metadataPath);
            return externalBaseUrl + metadataUrl;
        }
    }
}
