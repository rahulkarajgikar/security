package com.amazon.opendistroforelasticsearch.security.securityconf;

import java.util.List;

public abstract class WhitelistingSettingsModel {
    public abstract List<String> getWhitelistedAPIs();
    public abstract Boolean getIsWhitelistingEnabled();
}
