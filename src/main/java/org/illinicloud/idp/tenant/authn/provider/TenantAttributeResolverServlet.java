
package org.illinicloud.idp.tenant.authn.provider;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import edu.internet2.middleware.shibboleth.idp.profile.IdPProfileHandlerManager;
import org.illinicloud.idp.tenant.authn.TenantUsernamePasswordLoginHandler;
import org.ldaptive.*;
import org.ldaptive.Connection;
import org.ldaptive.auth.*;
import org.ldaptive.control.util.PagedResultsClient;
import org.ldaptive.pool.PooledConnectionFactory;
import org.opensaml.saml2.core.AuthnContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

import java.io.*;
import java.sql.*;
import java.util.*;


public class TenantAttributeResolverServlet extends HttpServlet {

    /** Serial version UID. */
    private static final long serialVersionUID = -572799841125956990L;

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(TenantAttributeResolverServlet.class);

    /** TenantUserNamePasswordLoginHandler is the bean in which the ldap connection pools are managed */
    private TenantUsernamePasswordLoginHandler loginHandler;

    /** Domain Authenticator */
    private Authenticator auth;

    /** LdapEntry to store results for DN lookup against ldap */
    LdapEntry ldapEntry;

    /** Constant used to represent request for full ldap retrieval */
    private static final String FULL_LDAP_REQUEST = "populateICFacts";

    /** Constant representing the action of publishing data to db cache */
    private static final String ACTION = "publish";

    /** List to store entries retrieved from full LDAP search */
    private List<LdapEntry> entryList;

    /** This is the jndi connection managed by the container */
    private String dbConnection = "java:comp/env/jdbc/FACTS";


    /** {@inheritDoc} */
    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        if (getInitParameter("jndiName") != null) {
            dbConnection = getInitParameter("jndiName");
        }

        ServletContext context = config.getServletContext();
        ApplicationContext appCtx = WebApplicationContextUtils.getWebApplicationContext(context);
        IdPProfileHandlerManager handlerManager = (IdPProfileHandlerManager)appCtx.getBean("shibboleth.HandlerManager");
        loginHandler = (TenantUsernamePasswordLoginHandler) handlerManager.getLoginHandlers().get(AuthnContext.PPT_AUTHN_CTX);

    }

    /** {@inheritDoc} */
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException,
            IOException {

        String principal = "";
        String user = "";
        String domain = "";
        String action = "";

        List<Map<String,Object>> attrs;
        ldapEntry = null;

        if (request.getParameter("userPrincipalName") != null)
            principal = request.getParameter("userPrincipalName").toLowerCase();
        if (request.getParameter("action") != null)
            action = request.getParameter("action").toLowerCase();

        if (!principal.equals("")) {
            int indexAmp = principal.indexOf('@');
            if (indexAmp > 0) {
                user = principal.substring(0, indexAmp);
                if (indexAmp != (principal.length() - 1)) {
                    domain = principal.substring(indexAmp + 1);
                }
            } else {
                log.error("The userPrincipalName in the request, {}, does not contain a domain specifier", principal);
                String json = new Gson().toJson("The userPrincipalName in the request, " + principal + " does not contain a domain specifier");
                response.setContentType("application/json");
                response.setCharacterEncoding("UTF-8");
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                response.getWriter().write(json);
                return;
            }
        } else {
            log.error("The principal parameter was not specified in the request");
            String json = new Gson().toJson("A userPrincipalName must be specified in the request");
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write(json);
            return;
        }

        if (!domain.equals("") && !user.equals("")) {
            log.debug("The user domain is {}", domain);
            auth = loginHandler.getTenantPools().get(domain);

            if (auth == null) {
                log.error("No ldap pool exists for the domain {}", domain);
                String json = new Gson().toJson("The domain " + domain + " cannot be contacted");
                response.setContentType("application/json");
                response.setCharacterEncoding("UTF-8");
                response.setStatus(HttpServletResponse.SC_NOT_FOUND);
                response.getWriter().write(json);
                return;
            }

            try {
                performLdapSearch(user);

                if (ldapEntry == null && entryList == null) {
                  log.error("The user {} doesn't exist in the domain {}",user,domain);
                  String json = new Gson().toJson("The user " + user + " does not exist in the domain " + domain);
                  response.setContentType("application/json");
                  response.setCharacterEncoding("UTF-8");
                  response.setStatus(HttpServletResponse.SC_NOT_FOUND);
                  response.getWriter().write(json);
                  return;
                }

                if (ldapEntry != null) {
                    attrs = buildJSON(ldapEntry);
                    if (!attrs.isEmpty()) {
                        Map<String, List> ldapAttributes = new HashMap<String, List>();
                        ldapAttributes.put("LDAPAttributes", attrs);
                        Gson gson = new GsonBuilder().disableHtmlEscaping().create();
                        String json = gson.toJson(ldapAttributes);
                        log.trace("Here is the json " + json);
                        response.setContentType("application/json");
                        response.setCharacterEncoding("UTF-8");
                        response.getWriter().write(json);
                        return;
                    }
                }

                if (entryList != null && !entryList.isEmpty()) {
                    response.setContentType("application/json");
                    response.setCharacterEncoding("UTF-8");
                    Gson gson = new GsonBuilder().disableHtmlEscaping().create();
                    String dbSessionId;

                    if (!action.equals("") && action.equalsIgnoreCase(ACTION)) {
                        dbSessionId = publish(domain);
                        Map<String,String> cid = new HashMap<String,String>();
                        cid.put("connection_id",dbSessionId);
                        String json = gson.toJson(cid);
                        response.getWriter().write(json);
                        return;
                    }
                    for (LdapEntry entry : entryList) {
                        attrs = buildJSON(entry);
                        Map<String,List> personAttributes = new HashMap<String,List>();
                        personAttributes.put("LDAPAttributes",attrs);
                        String json = gson.toJson(personAttributes);
                        response.getWriter().write(json);
                    }
                        response.getWriter().flush();
                        return;
                }

            } catch (LdapException e) {
                log.error(e.getMessage());
                String json = new Gson().toJson("An error occurred while fulfilling the request");
                response.setContentType("application/json");
                response.setCharacterEncoding("UTF-8");
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                response.getWriter().write(json);
            } catch (Exception ex) {
                log.error(ex.getMessage());
                Map<String,String> error = new HashMap<String,String>();
                error.put("status","failed");
                error.put("message", "An error occurred while fulfilling the request");
                error.put("error", ex.getMessage());
                String json = new Gson().toJson(error);
                response.setContentType("application/json");
                response.setCharacterEncoding("UTF-8");
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                response.getWriter().write(json);
            }
        } else {
            log.error("Bad request");
            String json = new Gson().toJson("Bad request. Specify a valid userPrincipalName.");
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write(json);
        }
    }

    protected void performLdapSearch(String user) throws LdapException {

        if (user.equalsIgnoreCase(FULL_LDAP_REQUEST)) {

            PooledBindAuthenticationHandler bah = (PooledBindAuthenticationHandler) auth.getAuthenticationHandler();
            PooledConnectionFactory pooledConnectionFactory = bah.getConnectionFactory();
            Connection connection = pooledConnectionFactory.getConnection();

            PooledSearchDnResolver dnResolver = (PooledSearchDnResolver) auth.getDnResolver();
            String searchDN = dnResolver.getBaseDn();
            String filter = "(&(|(ObjectCategory=person)(ObjectCategory=user))(ObjectClass=*))";
            String retAttrs = "*";
            entryList = new ArrayList<LdapEntry>();

            try {
                connection.open();
                PagedResultsClient client = new PagedResultsClient(connection, 50); // return 50 entries at a time
                SearchRequest searchRequest = new SearchRequest(searchDN,filter,retAttrs);
                Response<SearchResult> response = client.executeToCompletion(searchRequest);
                SearchResult result = response.getResult();
                for (LdapEntry entry : result.getEntries()) {
                    entryList.add(entry);
                }
            } catch (LdapException le) {
                log.error("Error opening connection to LDAP");
                throw le;
            } finally {
                if (connection.isOpen())
                    connection.close();
            }

        } else {
            String dn = auth.resolveDn(user);
            if (dn != null) {

                String userRoleAttribute = ReturnAttributes.ALL_USER.value()[0];
                AuthenticationRequest authenticationRequest = new AuthenticationRequest();
                authenticationRequest.setReturnAttributes(userRoleAttribute);

                PooledBindAuthenticationHandler bah = (PooledBindAuthenticationHandler) auth.getAuthenticationHandler();
                PooledConnectionFactory pooledConnectionFactory = bah.getConnectionFactory();
                Connection connection = pooledConnectionFactory.getConnection();
                PooledSearchEntryResolver pooledSearchEntryResolver = new PooledSearchEntryResolver(pooledConnectionFactory);

                AuthenticationHandlerResponse authenticationHandlerResponse = new AuthenticationHandlerResponse(true,ResultCode.SUCCESS,connection);
                AuthenticationCriteria authenticationCriteria = new AuthenticationCriteria(dn,authenticationRequest);

                ldapEntry = pooledSearchEntryResolver.resolve(authenticationCriteria,authenticationHandlerResponse);
                authenticationHandlerResponse.getConnection().close();
                if (connection.isOpen()) {
                    connection.close();
                }

            }
        }
    }

    protected List<Map<String,Object>> buildJSON (LdapEntry entry) {

        Map<String, Object> jsonString = new HashMap<String,Object>();
        List<Map<String,Object>> attrs = new ArrayList<Map<String,Object>>();
        for (final LdapAttribute ldapAttribute : entry.getAttributes()) {
            if(( ldapAttribute.getName().contains("msExch") ) ||
                    (ldapAttribute.getName().contains("protocolSettings")))
                continue;
            if( ldapAttribute.size() <= 1) {
                if( ldapAttribute.isBinary() ) {
                    jsonString.put("attributeName",ldapAttribute.getName());
                    jsonString.put("isBinary", "true");
                    jsonString.put("isMultiValue","false");
                    jsonString.put("attributeLength",ldapAttribute.size());
                    jsonString.put("attributeValue",ldapAttribute.getBinaryValue());

                } else {
                    jsonString.put("attributeName",ldapAttribute.getName());
                    jsonString.put("isBinary", "false");
                    jsonString.put("isMultiValue","false");
                    jsonString.put("attributeLength",ldapAttribute.size());

                    if ((ldapAttribute.getName().contains("objectGUID")) ||
                            (ldapAttribute.getName().contains("objectSid"))) {
                        String convertedValue = convertToByteString(ldapAttribute.getBinaryValue());
                        jsonString.put("attributeValue",convertedValue);
                    } else {
                        jsonString.put("attributeValue",ldapAttribute.getStringValue());
                    }
                }
            } else { // more than one value
                if( ldapAttribute.isBinary() ) {
                    jsonString.put("attributeName",ldapAttribute.getName());
                    jsonString.put("isBinary", "true");
                    jsonString.put("isMultiValue","true");
                    jsonString.put("attributeLength",ldapAttribute.size());
                    jsonString.put("attributeValue",ldapAttribute.getBinaryValues());
                } else {
                    jsonString.put("attributeName",ldapAttribute.getName());
                    jsonString.put("isBinary", "false");
                    jsonString.put("isMultiValue","true");
                    jsonString.put("attributeLength",ldapAttribute.size());
                    jsonString.put("attributeValue",ldapAttribute.getStringValues());
                }
            }
            attrs.add(jsonString);
            jsonString = new HashMap<String,Object>();
        }
        return attrs;
    }

    protected String publish(String domain) throws Exception {

        String sessionId = "0";
        String memberOf = "";
        String container = "";
        String sAMAccountName = "";
        java.sql.Connection connection = null;
        Statement statement = null;
        String query = "SELECT CONNECTION_ID();";

        try {
            Context initialContext = new InitialContext();
            DataSource dataSource = (DataSource)initialContext.lookup(dbConnection);
            if (dataSource != null) {
                connection = dataSource.getConnection();
            } else {
                log.error("Failed to lookup datasource");
                throw new Exception("Failed to lookup datasource");
            }

            log.trace("Running query to get connection id");
            statement = connection.createStatement();
            statement.execute("SET bulk_insert_buffer_size =1024*1024*256;");
            ResultSet rs = statement.executeQuery(query);
            while (rs.next()) {
                sessionId = rs.getString("CONNECTION_ID()");
            }
            rs.close();
            statement.close();
            log.trace("The connection id is {}", sessionId);

            CallableStatement callableStatement =
                    connection.prepareCall("{call publishFacts(?, ?, ?, ?, ?)}");

            for (LdapEntry entry : entryList) {
                for (final LdapAttribute ldapAttribute : entry.getAttributes()) {
                    if (ldapAttribute.getName().equalsIgnoreCase("memberOf")) {
                        if (!ldapAttribute.getStringValues().isEmpty()) {
                            Iterator it = ldapAttribute.getStringValues().iterator();
                            while (it.hasNext()) {
                                String member = (String) it.next();
                                if (memberOf.equals("")) {
                                    memberOf = member;
                                } else {
                                    memberOf = memberOf + "|" + member;
                                }
                            }
                        }
                    }
                    if (ldapAttribute.getName().equalsIgnoreCase("distinguishedName")) {
                        container = ldapAttribute.getStringValue();
                        Integer position = container.indexOf("OU=");
                        if (position > 0)
                            container = container.substring(container.indexOf("OU="));
                        else
                            container = "";
                    }
                    if (ldapAttribute.getName().equalsIgnoreCase("sAMAccountName")) {
                        sAMAccountName = ldapAttribute.getStringValue();
                    }
                }

                if (memberOf != "") {
                    callableStatement.setString(1, domain);
                    callableStatement.setString(2, "IDP");
                    callableStatement.setString(3, sAMAccountName);
                    callableStatement.setString(4, memberOf);
                    callableStatement.setString(5, "|");
                    callableStatement.addBatch();
                }
                if (container != "") {
                    callableStatement.setString(1, domain);
                    callableStatement.setString(2, "IDP");
                    callableStatement.setString(3, sAMAccountName);
                    callableStatement.setString(4, container);
                    callableStatement.setString(5, "|");
                    callableStatement.addBatch();
                }
                memberOf = "";
            }
            log.trace("Execute batch of function calls against the DB");
            int[] updateCounts = callableStatement.executeBatch();
            callableStatement.close();
            connection.close();

        } catch (Exception ex) {
            log.error("Failed to publish the directory data to the db cache");
            throw ex;
        } finally {
            if (!connection.isClosed())
                connection.close();
        }

        return sessionId;
    }

    private static String convertToByteString(byte[] objectGUID) {
        StringBuilder result = new StringBuilder();

        for (int i = 0; i < objectGUID.length; i++) {
            String transformed = prefixZeros((int) objectGUID[i] & 0xFF);
            result.append("\\");
            result.append(transformed);
        }

        return result.toString();
    }

    private static String prefixZeros(int value) {
        if (value <= 0xF) {
            StringBuilder sb = new StringBuilder("0");
            sb.append(Integer.toHexString(value));

            return sb.toString();

        } else {
            return Integer.toHexString(value);
        }
    }
}
