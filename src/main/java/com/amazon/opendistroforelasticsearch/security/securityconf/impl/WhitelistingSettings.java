package com.amazon.opendistroforelasticsearch.security.securityconf.impl;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class WhitelistingSettings {
    @JsonProperty(value = "isWhitelistingEnabled")
    private boolean isWhitelistingEnabled;
    @JsonProperty(value = "whitelistedAPIs")
    private List<String> whitelistedAPIs;

    public WhitelistingSettings(){
        isWhitelistingEnabled = false;
        whitelistedAPIs = new ArrayList<>(Arrays.asList(
                "/_cat/plugins",
                "/_cluster/health",
                "/_cat/nodes"
        ));
    }
    public WhitelistingSettings(WhitelistingSettings whitelistingSettings){
        this.isWhitelistingEnabled = whitelistingSettings.getIsWhitelistingEnabled();
        this.whitelistedAPIs = whitelistingSettings.getWhitelistedAPIs();
    }

    @JsonProperty(value = "isWhitelistingEnabled")
    public boolean getIsWhitelistingEnabled() {
        return this.isWhitelistingEnabled;
    }

    @JsonProperty(value = "isWhitelistingEnabled")
    public void setIsWhitelistingEnabled(Boolean isWhitelistingEnabled) {
        this.isWhitelistingEnabled = isWhitelistingEnabled;
    }

    @JsonProperty(value = "whitelistedAPIs")
    public List<String> getWhitelistedAPIs() {
        return this.whitelistedAPIs;
    }

    @JsonProperty(value = "whitelistedAPIs")
    public void setWhitelistedAPIs(List<String> whitelistedAPIs) {
        this.whitelistedAPIs = whitelistedAPIs;
    }

    @Override
    public String toString() {
        return "WhitelistingSetting [isWhitelistingEnabled=" + isWhitelistingEnabled + ", whitelistedAPIs=" + whitelistedAPIs +']';
    }
}
