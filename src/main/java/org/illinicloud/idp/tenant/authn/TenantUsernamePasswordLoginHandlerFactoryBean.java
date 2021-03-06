package org.illinicloud.idp.tenant.authn;

import edu.internet2.middleware.shibboleth.idp.config.profile.authn.AbstractLoginHandlerFactoryBean;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.Map;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;

import org.ldaptive.*;
import org.ldaptive.auth.PooledSearchDnResolver;
import org.ldaptive.auth.SearchDnResolver;
import org.ldaptive.pool.*;
import org.ldaptive.provider.jndi.JndiProvider;
import org.ldaptive.provider.jndi.JndiProviderConfig;
import org.ldaptive.ssl.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TenantUsernamePasswordLoginHandlerFactoryBean extends AbstractLoginHandlerFactoryBean {

    private final Logger log = LoggerFactory.getLogger(TenantUsernamePasswordLoginHandlerFactoryBean.class);
    private String authenticationServletURL;
    private String jndiName;
    private StandardPBEStringEncryptor encryptor;
    private Integer minSize;
    private Integer maxSize;
    private Map<String,Map> tenants = new HashMap<String, Map>();
    private Map<String,SoftLimitConnectionPool> pools = new HashMap<String, SoftLimitConnectionPool>();
    private Map<String, PooledSearchDnResolver> dnResolvers = new HashMap<String, PooledSearchDnResolver>();

    public String getAuthenticationServletURL() {
        return authenticationServletURL;
    }

    public void setAuthenticationServletURL(String url) {
        authenticationServletURL = url;
    }

    public String getJndiName() {
        return jndiName;
    }

    public void setJndiName(String name) {
        jndiName = name;
    }

    public void setEncryptor(StandardPBEStringEncryptor enc) {
        encryptor = enc;
    }

    public Integer getMinSize() { return minSize; }

    public void setMinSize(Integer lowEnd) { minSize = lowEnd; }

    public Integer getMaxSize() { return maxSize; }

    public void setMaxSize(Integer topEnd) { maxSize = topEnd; }

    public void setTenants(Map<String,Map> tenantConfigs) {
        tenants = tenantConfigs;
    }


    /** {@inheritDoc} */
    protected Object createInstance() throws Exception {

        TenantUsernamePasswordLoginHandler handler = new TenantUsernamePasswordLoginHandler(authenticationServletURL);
        populateHandler(handler);

        getTenantConfigs();
        initializePools();
        /*handler.setTenantPools(authPools);*/
        /*handler.setConnFactoryPools(factoryPools);*/
        handler.setPools(pools);
        handler.setSearchDnResolvers(dnResolvers);
        handler.setEncryptor(encryptor);
        return handler;
    }

    /** {@inheritDoc} */
    public Class getObjectType() {
        return TenantUsernamePasswordLoginHandler.class;
    }

    protected void getTenantConfigs() throws Exception {

        Connection connection = null;
        Statement statement = null;



        String query = new StringBuilder().append("select o.name, c.host_name, c.port, c.account, c.password, f.auth_attribute, f.search_base, 'subtree' as scope ")
                .append("from organization o, connection c, filter f, entity_descriptor e, idpproxy_tenant i, data_store d ")
                .append("where o.id = e.organization_id AND ")
                .append("i.entity_descriptor_id = e.id AND ")
                .append("i.id = d.idp_proxy_tenant_id AND ")
                .append("d.connection_id = c.id AND ")
                .append("d.filter_id = f.id AND ")
                .append("d.data_store_type_id = 1 AND ")
                .append("e.approved = 1 AND ")
                .append("e.active = 1 AND ")
                .append("(o.primary_id = 2 or o.primary_id = 3);").toString();

        try {
            Context initialContext = new InitialContext();
            DataSource dataSource = (DataSource)initialContext.lookup(jndiName);
            if (dataSource != null) {
                connection = dataSource.getConnection();
            } else {
                log.error("Failed to lookup datasource");
                throw new Exception("Failed to lookup datasource");
            }
            statement = connection.createStatement();
            ResultSet rs = statement.executeQuery(query);
            while (rs.next()) {
                String domainName = rs.getString("name");
                String hostName = rs.getString("host_name");
                String port = rs.getString("port");
                String account = rs.getString("account");
                String password = rs.getString("password");
                password = encryptor.decrypt(password);
                String key = rs.getString("auth_attribute");
                String searchBase = rs.getString("search_base");
                String scope = rs.getString("scope");

                Map<String, String> connInfo = new HashMap<String, String>();
                connInfo.put("host", hostName);
                connInfo.put("port", port);
                connInfo.put("account", account);
                connInfo.put("password", password);
                connInfo.put("filter", key);
                connInfo.put("baseDN", searchBase);
                connInfo.put("scope", scope);

                tenants.put(domainName, connInfo);
            }
            rs.close();
        } catch (NamingException ne) {
            log.error("Error initializing naming context to retrieve JNDI connection");
            throw new Exception(ne.getMessage());
        } catch (SQLException ex) {
            log.error("Error getting connection to database or querying database");
            throw new Exception(ex.getMessage());
        } finally {
            if (statement != null) {
                statement.close();
            }
            if (connection != null) {
                connection.close();
            }
        }
    }

    protected void initializePools() {

        log.info("Initializing district connection pools");
        Integer timeout = new Integer (5000);
        Integer validatePeriod = new Integer (300);

        KeyStoreCredentialConfig credentialConfig = new KeyStoreCredentialConfig();
        credentialConfig.setTrustStore("classpath:/cacerts");
        credentialConfig.setTrustStorePassword("changeit");

        for (Map.Entry<String, Map> entry : tenants.entrySet()) {

            String key = entry.getKey();
            Map<String,String> value = entry.getValue();

            PoolConfig poolConfig = new PoolConfig();
            poolConfig.setMinPoolSize(minSize);
            poolConfig.setMaxPoolSize(maxSize);
            poolConfig.setValidatePeriodically(true);
            poolConfig.setValidatePeriod(validatePeriod.longValue());
            poolConfig.setValidateOnCheckOut(true);
            AllowAnyHostnameVerifier allowAnyHostnameVerifier = new AllowAnyHostnameVerifier();
            SslConfig sslConfig = new SslConfig(credentialConfig);

            String ldapURL = "ldap://" + value.get("host") + ":" + value.get("port");
            ConnectionConfig connectionConfig = new ConnectionConfig();
            connectionConfig.setSslConfig(sslConfig);
            connectionConfig.setUseSSL(true);
            connectionConfig.setConnectTimeout(timeout.longValue());
            connectionConfig.setResponseTimeout(timeout.longValue());
            connectionConfig.setLdapUrl(ldapURL);
            connectionConfig.setConnectionInitializer(new BindConnectionInitializer(value.get("account"), new Credential(value.get("password"))));

            TLSSocketFactory tlsSocketFactory = new TLSSocketFactory();
            JndiProviderConfig jndiProviderConfig = new JndiProviderConfig();
            jndiProviderConfig.setSslSocketFactory(tlsSocketFactory);
            jndiProviderConfig.setHostnameVerifier(allowAnyHostnameVerifier);
            JndiProvider jndiProvider = new JndiProvider();
            jndiProvider.setProviderConfig(jndiProviderConfig);
            DefaultConnectionFactory cf = new DefaultConnectionFactory(connectionConfig,jndiProvider);

            SoftLimitConnectionPool pool = new SoftLimitConnectionPool(poolConfig, cf);
            pool.setName(key);
            pool.setValidator(new SearchValidator());
            SoftLimitConnectionPool dnResolverPool = new SoftLimitConnectionPool(poolConfig,cf);
            dnResolverPool.setName("dnResolver"+key);
            dnResolverPool.setValidator(new SearchValidator());

            try {
                pool.initialize();
            } catch (IllegalStateException e) {
                log.error("Unable to initialize ldap connection pool for host {}", ldapURL);
                log.error(e.getMessage());
            }

            try {
                dnResolverPool.initialize();
            } catch (IllegalStateException e) {
                log.error("Unable to initialize dnResolver connection pool for host {}", ldapURL);
                log.error(e.getMessage());
            }


            /*SearchDnResolver dnResolver = new SearchDnResolver();
            dnResolver.setBaseDn(value.get("baseDN"));
            dnResolver.setUserFilter("(" + value.get("filter") + "={user})");
            dnResolver.setSubtreeSearch(true);
            dnResolver.setConnectionFactory(cf);*/
            PooledSearchDnResolver dnResolver = new PooledSearchDnResolver(new PooledConnectionFactory(dnResolverPool));
            dnResolver.setBaseDn(value.get("baseDN"));
            dnResolver.setUserFilter("(" + value.get("filter") + "={user})");
            dnResolver.setSubtreeSearch(true);
            pools.put(key, pool);
            dnResolvers.put(key,dnResolver);
        }
    }

}
