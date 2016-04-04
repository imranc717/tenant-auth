package org.illinicloud.idp.tenant.authn.resolver;


import edu.internet2.middleware.shibboleth.common.config.attribute.resolver.dataConnector.BaseDataConnectorFactoryBean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TenantAttributeResolverFactoryBean extends BaseDataConnectorFactoryBean {

    private final Logger log = LoggerFactory.getLogger(TenantAttributeResolverFactoryBean.class);

    private String endpoint;

    public void setEndpoint(String url) {
        endpoint = url;
    }

    public String getEndpoint() {
        return endpoint;
    }

    public Class getObjectType() {
        return TenantAttributeResolver.class;
    }

    protected Object createInstance() throws Exception {
        log.debug("The endpoint is {}", endpoint);
        TenantAttributeResolver connector = new TenantAttributeResolver(endpoint);
        populateDataConnector(connector);
        return connector;
    }

}
