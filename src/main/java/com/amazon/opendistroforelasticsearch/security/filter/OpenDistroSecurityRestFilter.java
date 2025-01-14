/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.filter;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

import javax.net.ssl.SSLPeerUnverifiedException;

import com.amazon.opendistroforelasticsearch.security.configuration.AdminDNs;
import com.amazon.opendistroforelasticsearch.security.securityconf.WhitelistingSettingsModel;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.WhitelistingSettings;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestHandler;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.threadpool.ThreadPool;

import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog.Origin;
import com.amazon.opendistroforelasticsearch.security.auth.BackendRegistry;
import com.amazon.opendistroforelasticsearch.security.configuration.CompatConfig;
import com.amazon.opendistroforelasticsearch.security.ssl.transport.PrincipalExtractor;
import com.amazon.opendistroforelasticsearch.security.ssl.util.ExceptionUtils;
import com.amazon.opendistroforelasticsearch.security.ssl.util.SSLRequestHelper;
import com.amazon.opendistroforelasticsearch.security.ssl.util.SSLRequestHelper.SSLInfo;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.HTTPHelper;
import com.amazon.opendistroforelasticsearch.security.user.User;
import org.greenrobot.eventbus.Subscribe;

public class OpenDistroSecurityRestFilter {

    protected final Logger log = LogManager.getLogger(this.getClass());
    private final BackendRegistry registry;
    private final AuditLog auditLog;
    private final ThreadContext threadContext;
    private final PrincipalExtractor principalExtractor;
    private final Settings settings;
    private final Path configPath;
    private final CompatConfig compatConfig;
    private static final List<String> defaultWhitelistedAPIs = new ArrayList<>(Arrays.asList(
            "/_cat/plugins",
            "/_cluster/health",
            "/_cat/nodes"
    ));
    private static final Boolean defaultWhitelistingEnabled = false;

    private boolean whitelistingEnabled;
    private HashSet<String> whitelistedAPIs;


    public OpenDistroSecurityRestFilter(final BackendRegistry registry, final AuditLog auditLog,
            final ThreadPool threadPool, final PrincipalExtractor principalExtractor,
            final Settings settings, final Path configPath, final CompatConfig compatConfig) {
        super();
        this.registry = registry;
        this.auditLog = auditLog;
        this.threadContext = threadPool.getThreadContext();
        this.principalExtractor = principalExtractor;
        this.settings = settings;
        this.configPath = configPath;
        this.compatConfig = compatConfig;
        this.whitelistingEnabled = false;
        this.whitelistedAPIs = new HashSet<>(defaultWhitelistedAPIs);

    }

    /**
     * This function wraps around all rest requests
     * If the request is authenticated, then it goes through a whitelisting check.
     * The whitelisting check works as follows:
     * If whitelisting is not enabled, then requests are handled normally.
     * If whitelisting is enabled, then SuperAdmin is allowed access to all APIs, regardless of what is currently whitelisted.
     * If whitelisting is enabled, then Non-SuperAdmin is allowed to access only those APIs that are whitelisted in {@link #whitelistedAPIs}
     * For example: if whitelisting is enabled and whitelistedAPIs = ["/_cat/nodes"], then SuperAdmin can access all APIs, but non SuperAdmin
     * can only access "/_cat/nodes"
     * Note: if whitelistedAPIs = ["/_cat/nodes"] is whitelisted, "/_cat/nodes/" will not work, because of the extra '/'.
     * Further note: Some APIs are only accessible by SuperAdmin, regardless of whitelisting. For example: /_opendistro/_security/api/whitelist is only accessible by SuperAdmin.
     * See {@link com.amazon.opendistroforelasticsearch.security.dlic.rest.api.WhitelistApiAction} for the implementation of this API.
     * SuperAdmin is identified by credentials, which can be passed in the curl request.
     */
    public RestHandler wrap(RestHandler original, AdminDNs adminDNs) {
        return new RestHandler() {
            
            @Override
            public void handleRequest(RestRequest request, RestChannel channel, NodeClient client) throws Exception {
                org.apache.logging.log4j.ThreadContext.clearAll();
                if (!checkAndAuthenticateRequest(request, channel, client)) {
                    User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
                    if (userIsSuperAdmin(user, adminDNs) || checkRequestIsWhitelisted(request, channel, client)) {
                        original.handleRequest(request, channel, client);
                    }
                }
            }
        };
    }

    /**
     * Checks if a given user is a SuperAdmin
     */
    private Boolean userIsSuperAdmin(User user, AdminDNs adminDNs) {
        if (user != null && adminDNs.isAdmin(user)) {
            return true;
        }
        return false;
    }

    /**
     * Helper function to generate an error when an unauthorized user (i.e non superadmin) tries to access an API that is not whitelisted.
     */
    private BytesRestResponse createNotWhitelistedErrorResponse(RestChannel channel, String errorMessage,
                                                                RestStatus status) throws IOException {
        return new BytesRestResponse(status, channel.newErrorBuilder().startObject()
                .field("error", errorMessage)
                .field("status", status.getStatus())
                .endObject());
    }

    /**
     * Checks against {@link #whitelistedAPIs} that a given request path is whitelisted, for non SuperAdmin .
     * For SuperAdmin this function is bypassed.
     * For example: if "/_cat/nodes" is whitelisted, then it will be an, allowed request, otherwise will not be.
     * Note: currently, if "/_cat/nodes" is whitelisted, then "/_cat/nodes/" will not be allowed, because the path is different.
     * In a future version, could add a regex check to improve the functionality.
     */
    private boolean checkRequestIsWhitelisted(RestRequest request, RestChannel channel,
                                              NodeClient client) throws IOException {
        //if whitelisting is enabled but the request path is not whitelisted then return false, otherwise true.
        if (this.whitelistingEnabled && !this.whitelistedAPIs.contains(request.path())) {
            channel.sendResponse(createNotWhitelistedErrorResponse(
                    channel,
                    request.path() + " API not whitelisted",
                    RestStatus.FORBIDDEN
            ));
            return false;
        }
        return true;
    }


    private boolean checkAndAuthenticateRequest(RestRequest request, RestChannel channel,
                                                NodeClient client) throws Exception {

        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN, Origin.REST.toString());
        
        if(HTTPHelper.containsBadHeader(request)) {
            final ElasticsearchException exception = ExceptionUtils.createBadHeaderException();
            log.error(exception);
            auditLog.logBadHeaders(request);
            channel.sendResponse(new BytesRestResponse(channel, RestStatus.FORBIDDEN, exception));
            return true;
        }
        
        if(SSLRequestHelper.containsBadHeader(threadContext, ConfigConstants.OPENDISTRO_SECURITY_CONFIG_PREFIX)) {
            final ElasticsearchException exception = ExceptionUtils.createBadHeaderException();
            log.error(exception);
            auditLog.logBadHeaders(request);
            channel.sendResponse(new BytesRestResponse(channel, RestStatus.FORBIDDEN, exception));
            return true;
        }

        final SSLInfo sslInfo;
        try {
            if((sslInfo = SSLRequestHelper.getSSLInfo(settings, configPath, request, principalExtractor)) != null) {
                if(sslInfo.getPrincipal() != null) {
                    threadContext.putTransient("_opendistro_security_ssl_principal", sslInfo.getPrincipal());
                }
                
                if(sslInfo.getX509Certs() != null) {
                     threadContext.putTransient("_opendistro_security_ssl_peer_certificates", sslInfo.getX509Certs());
                }
                threadContext.putTransient("_opendistro_security_ssl_protocol", sslInfo.getProtocol());
                threadContext.putTransient("_opendistro_security_ssl_cipher", sslInfo.getCipher());
            }
        } catch (SSLPeerUnverifiedException e) {
            log.error("No ssl info", e);
            auditLog.logSSLException(request, e);
            channel.sendResponse(new BytesRestResponse(channel, RestStatus.FORBIDDEN, e));
            return true;
        }
        
        if(!compatConfig.restAuthEnabled()) {
            return false;
        }

        if(request.method() != Method.OPTIONS 
                && !"/_opendistro/_security/health".equals(request.path())) {
            if (!registry.authenticate(request, channel, threadContext)) {
                // another roundtrip
                org.apache.logging.log4j.ThreadContext.remove("user");
                return true;
            } else {
                // make it possible to filter logs by username
                org.apache.logging.log4j.ThreadContext.put("user", ((User)threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER)).getName());
            }
        }
        
        return false;
    }

    @Subscribe
    public void onWhitelistingSettingChanged(WhitelistingSettingsModel whitelistingSettingsModel) {
        WhitelistingSettings whitelistingSettings = whitelistingSettingsModel.getWhitelistingSettings();
        this.whitelistingEnabled = (whitelistingSettings == null ? defaultWhitelistingEnabled : whitelistingSettings.getWhitelistingEnabled());
        this.whitelistedAPIs = new HashSet<>((whitelistingSettings == null || whitelistingSettings.getWhitelistedAPIs() == null) ? defaultWhitelistedAPIs : whitelistingSettings.getWhitelistedAPIs());
    }
}
