package org.illinicloud.idp.tenant.authn;

import edu.internet2.middleware.shibboleth.common.config.BaseSpringNamespaceHandler;

public class TenantAuthnNamespaceHandler extends BaseSpringNamespaceHandler {
    public static final String NAMESPACE = "http://illinicloud.org/idp/tenant/authn";

    public void init()
    {
        registerBeanDefinitionParser(TenantUsernamePasswordLoginHandlerBeanDefinitionParser.SCHEMA_TYPE, new TenantUsernamePasswordLoginHandlerBeanDefinitionParser());
    }
}
