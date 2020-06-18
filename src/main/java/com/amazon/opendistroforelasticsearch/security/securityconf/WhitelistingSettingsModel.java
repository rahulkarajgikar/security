package com.amazon.opendistroforelasticsearch.security.securityconf;

import java.util.HashSet;

public abstract class WhitelistingSettingsModel {
    public abstract HashSet<String> getWhitelistedAPIs();
    public abstract Boolean getIsWhitelistingEnabled();

}
