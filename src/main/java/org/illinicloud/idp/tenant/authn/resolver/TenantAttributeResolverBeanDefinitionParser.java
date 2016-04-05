package org.illinicloud.idp.tenant.authn.resolver;

import edu.internet2.middleware.shibboleth.common.config.attribute.resolver.dataConnector.BaseDataConnectorBeanDefinitionParser;
import javax.xml.namespace.QName;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.ParserContext;
import org.w3c.dom.Element;

import java.util.List;
import java.util.Map;


public class TenantAttributeResolverBeanDefinitionParser extends BaseDataConnectorBeanDefinitionParser {

    public static final QName SCHEMA_NAME = new QName(TenantAttributeNamespaceHandler.NAMESPACE, "AttributeService");

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(TenantAttributeResolverBeanDefinitionParser.class);

    protected Class getBeanClass(Element element) {
        return TenantAttributeResolverFactoryBean.class;
    }

    protected void doParse(String pluginId, Element pluginConfig, Map<QName, List<Element>> pluginConfigChildren,
                           BeanDefinitionBuilder pluginBuilder, ParserContext parserContext) {
        super.doParse(pluginId, pluginConfig, pluginConfigChildren, pluginBuilder, parserContext);

        log.debug("In BeanDefinitionParser for TenantResolver");

        /** Add property value for endpoint */
        if (pluginConfig.hasAttributeNS(null, "lookupUrl")) {
            log.debug("The lookupUrl read from the connector definition is {}",
                    pluginConfig.getAttributeNS(null, "lookupUrl"));
            pluginBuilder.addPropertyValue("endpoint", pluginConfig.getAttributeNS(null,
                    "lookupUrl"));
        } else {
            log.error("Unable to read lookupUrl from the connector definition");
        }
    }
}

