package com.amazon.opendistroforelasticsearch.security.dlic.rest.api;

import com.amazon.opendistroforelasticsearch.security.DefaultObjectMapper;
import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.configuration.AdminDNs;
import com.amazon.opendistroforelasticsearch.security.configuration.ConfigurationRepository;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.RolesMappingValidator;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.WhitelistValidator;
import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesEvaluator;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.CType;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.SecurityDynamicConfiguration;
import com.amazon.opendistroforelasticsearch.security.ssl.transport.PrincipalExtractor;
import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.collect.ImmutableList;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.threadpool.ThreadPool;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

public class WhitelistApiAction extends AbstractApiAction {
    private static final List<Route> routes = ImmutableList.of(
            new Route(RestRequest.Method.GET, "/_opendistro/_security/api/whitelist/"),
            //new Route(RestRequest.Method.DELETE, "/_opendistro/_security/api/whitelisting/{name}"),
            new Route(RestRequest.Method.PUT, "/_opendistro/_security/api/whitelist/")
            //new Route(RestRequest.Method.PATCH, "/_opendistro/_security/api/whitelist/{name}")
    );

    private static final String name = "whitelisting_settings";

    @Inject
    public WhitelistApiAction(final Settings settings, final Path configPath, final RestController controller, final Client client,
                                 final AdminDNs adminDNs, final ConfigurationRepository cl, final ClusterService cs,
                                 final PrincipalExtractor principalExtractor, final PrivilegesEvaluator evaluator, ThreadPool threadPool, AuditLog auditLog) {
        super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool, auditLog);
    }

    @Override
    protected void handleApiRequest(final RestChannel channel, final RestRequest request, final Client client) throws IOException {
        //TODO: Add this part back later and figure out a way to become super user.
        /*
        if (!isSuperAdmin()) {
            forbidden(channel, "API allowed only for super admin.");
            return;
        }
        */
        super.handleApiRequest(channel, request, client);
    }
    //POST,DELETE,PUT DONE.
    //NOW DO GET
    @Override
    protected void handleGet(final RestChannel channel, RestRequest request, Client client, final JsonNode content)
            throws IOException{


        final SecurityDynamicConfiguration<?> configuration = load(getConfigName(), true);
        filter(configuration);
        successResponse(channel, configuration);
        return;
    }

    @Override
    protected void handleDelete(final RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException {
        notImplemented(channel, RestRequest.Method.DELETE);
    }

    @Override
    protected void handlePut(final RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException {
        final SecurityDynamicConfiguration<?> existingConfiguration = load(getConfigName(), false);

        //MIGHT NOT NEED THIS
        if (existingConfiguration.getSeqNo() < 0) {
            forbidden(channel, "Security index need to be updated to support '" + getConfigName().toLCString() + "'. Use OpenDistroSecurityAdmin to populate.");
            return;
        }

        boolean existed = existingConfiguration.exists(name);
        existingConfiguration.putCObject(name, DefaultObjectMapper.readTree(content, existingConfiguration.getImplementingClass()));

        saveAnUpdateConfigs(client, request, getConfigName(), existingConfiguration, new OnSucessActionListener<IndexResponse>(channel) {

            @Override
            public void onResponse(IndexResponse response) {
                if (existed) {
                    successResponse(channel, "'" + name + "' updated.");
                } else {
                    createdResponse(channel, "'" + name + "' created.");
                }
            }
        });
    }


    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    protected Endpoint getEndpoint() {
        return Endpoint.WHITELIST;
    }

    @Override
    protected AbstractConfigurationValidator getValidator(RestRequest request, BytesReference ref, Object... param) {
        return new WhitelistValidator(request, ref, this.settings, param);
    }

    @Override
    protected String getResourceName() {
        return name;
    }

    @Override
    protected CType getConfigName() {
        return CType.WHITELISTING_SETTINGS;
    }

}
