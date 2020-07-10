package com.amazon.opendistroforelasticsearch.security.securityconf.impl;

import java.util.Collections;
import java.util.List;
import java.util.Map;

public class WhitelistingSettings {
    private boolean enabled;
    private Map<String, List<HttpRequestMethods>> requests;

    /**
     * Used to parse the yml files, do not remove.
     */
    public WhitelistingSettings() {
        enabled = false;
        requests = Collections.emptyMap();
    }

    public WhitelistingSettings(WhitelistingSettings whitelistingSettings) {
        this.enabled = whitelistingSettings.getEnabled();
        this.requests = whitelistingSettings.getRequests();
    }

    public boolean getEnabled() {
        return this.enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Map<String, List<HttpRequestMethods>> getRequests() {
        return this.requests == null ? Collections.emptyMap(): this.requests;
    }

    public void setRequests(Map<String, List<HttpRequestMethods>> requests) {
        this.requests = requests;
    }

    @Override
    public String toString() {
        return "WhitelistingSetting [enabled=" + enabled + ", requests=" + requests + ']';
    }
}
