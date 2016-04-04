package org.illinicloud.idp.tenant.authn.resolver;


import edu.internet2.middleware.shibboleth.common.config.BaseSpringNamespaceHandler;

public class TenantAttributeNamespaceHandler extends BaseSpringNamespaceHandler {

    public static final String NAMESPACE = "http://illinicloud.org/idp/tenant/authn/resolver";

    public void init()
    {
        registerBeanDefinitionParser(TenantAttributeResolverBeanDefinitionParser.SCHEMA_NAME,
                new TenantAttributeResolverBeanDefinitionParser());
    }
}
