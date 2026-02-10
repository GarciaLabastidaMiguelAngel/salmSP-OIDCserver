package com.authserver.oidc.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for SAML2 debugging.
 * Only active in dev/preprod profiles for security.
 */
@ConfigurationProperties(prefix = "saml.debug-authn-request")
public class SamlDebugProperties {
    
    /**
     * Enable/disable AuthnRequest XML logging.
     * Only effective in dev/preprod profiles (hard-blocked in prod).
     * When enabled, logs COMPLETE XML without truncation.
     */
    private boolean enabled = false;
    
    /**
     * Enable pretty-print formatting of XML output.
     * Default false (shows raw XML as-is for exact reproduction).
     */
    private boolean prettyPrint = false;
    
    public boolean isEnabled() {
        return enabled;
    }
    
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
    
    public boolean isPrettyPrint() {
        return prettyPrint;
    }
    
    public void setPrettyPrint(boolean prettyPrint) {
        this.prettyPrint = prettyPrint;
    }
}
