package org.illinicloud.idp.tenant.authn;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.opensaml.xml.util.DatatypeHelper;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.w3c.dom.Element;
import edu.internet2.middleware.shibboleth.idp.config.profile.authn.AbstractLoginHandlerBeanDefinitionParser;
import javax.xml.namespace.QName;
import java.util.List;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;

public class TenantUsernamePasswordLoginHandlerBeanDefinitionParser extends AbstractLoginHandlerBeanDefinitionParser {

    /** Schema type. */
    public static final QName SCHEMA_TYPE = new QName(TenantAuthnNamespaceHandler.NAMESPACE, "TenantUsernamePassword");

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(TenantUsernamePasswordLoginHandlerBeanDefinitionParser.class);

    /** {@inheritDoc} */
    protected Class getBeanClass(Element element) {
        return TenantUsernamePasswordLoginHandlerFactoryBean.class;
    }

    /** {@inheritDoc} */
    protected void doParse(Element config, BeanDefinitionBuilder builder) {

        super.doParse(config, builder);

        /** add Property Value for authenticationServletURL */
        if (config.hasAttributeNS(null, "authenticationServletURL")) {
            builder.addPropertyValue("authenticationServletURL", DatatypeHelper.safeTrim(config.getAttributeNS(null,
                    "authenticationServletURL")));
        } else {
            builder.addPropertyValue("authenticationServletURL", "/Authn/Tenant/Login");
        }

        /** parse Encryption configuration element */
        List<Element> encryption = XMLHelper.getChildElementsByTagNameNS(config, "http://illinicloud.org/idp/tenant/authn", "Encryption");
        if ((encryption == null) || (encryption.isEmpty())) {
            throw new BeanCreationException("An encryption setting configuration must be specified.");
        }

        /** add Property Value for algorithm */
        String algorithm;
        List<Element> algorithms = XMLHelper.getChildElementsByTagNameNS(encryption.get(0), "http://illinicloud.org/idp/tenant/authn", "algorithm");
        if ((algorithms == null) || (algorithms.size() != 1))
        {
            String msg = String.format("%s, an unique '%s' element was excepted.", new Object[] { encryption.get(0).getNodeName(), "algorithm" });
            throw new BeanCreationException(msg);
        }
        algorithm = algorithms.get(0).getTextContent();
        /*builder.addPropertyValue("encAlgorithm", algorithm);*/

        /** add Property Value for password */
        String password;
        List<Element> passwords = XMLHelper.getChildElementsByTagNameNS(encryption.get(0), "http://illinicloud.org/idp/tenant/authn", "password");
        if ((passwords == null) || (passwords.size() != 1))
        {
            String msg = String.format("%s, an unique '%s' element was excepted.", new Object[] { encryption.get(0).getNodeName(), "password" });
            throw new BeanCreationException(msg);
        }
        password = passwords.get(0).getTextContent();
        /*builder.addPropertyValue("encPassword", password);*/

        StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
        encryptor.setAlgorithm(algorithm);
        encryptor.setPassword(password);
        encryptor.setKeyObtentionIterations(1000);
        encryptor.setProvider(new BouncyCastleProvider());

        builder.addPropertyValue("encryptor", encryptor);


        /** parse Database configuration element */
        List<Element> database = XMLHelper.getChildElementsByTagNameNS(config, "http://illinicloud.org/idp/tenant/authn", "Database");
        if ((database == null) || (database.isEmpty())) {
            throw new BeanCreationException("An database configuration element must be specified.");
        }

        /** add Property Value for jndiName */
        String jndiName;
        List<Element> names = XMLHelper.getChildElementsByTagNameNS(database.get(0), "http://illinicloud.org/idp/tenant/authn", "jndiName");
        if ((names == null) || (names.size() != 1))
        {
            String msg = String.format("%s, an unique '%s' element was excepted.", new Object[] { database.get(0).getNodeName(), "jndiName" });
            throw new BeanCreationException(msg);
        }
        jndiName = names.get(0).getTextContent();
        builder.addPropertyValue("jndiName", jndiName);

        /** parse PoolSettings configuration element */
        List<Element> poolSettings = XMLHelper.getChildElementsByTagNameNS(config, "http://illinicloud.org/idp/tenant/authn", "PoolSettings");
        if ((poolSettings == null) || (poolSettings.isEmpty())) {
            throw new BeanCreationException("A pool setting configuration must be specified.");
        }

        /** add Property Value for minSize */
        int minSize;
        List<Element> lowEnd = XMLHelper.getChildElementsByTagNameNS(poolSettings.get(0), "http://illinicloud.org/idp/tenant/authn", "minSize");
        if ((lowEnd == null) || (lowEnd.size() != 1))
        {
            String msg = String.format("%s, an unique '%s' element was excepted.", new Object[] { encryption.get(0).getNodeName(), "minSize" });
            throw new BeanCreationException(msg);
        }
        minSize = Integer.parseInt(lowEnd.get(0).getTextContent());
        builder.addPropertyValue("minSize", minSize);

        /** add Property Value for maxSize */
        int maxSize;
        List<Element> topEnd = XMLHelper.getChildElementsByTagNameNS(poolSettings.get(0), "http://illinicloud.org/idp/tenant/authn", "maxSize");
        if ((topEnd == null) || (topEnd.size() != 1))
        {
            String msg = String.format("%s, an unique '%s' element was excepted.", new Object[] { encryption.get(0).getNodeName(), "maxSize" });
            throw new BeanCreationException(msg);
        }
        maxSize = Integer.parseInt(topEnd.get(0).getTextContent());
        builder.addPropertyValue("maxSize", maxSize);

    }
}
