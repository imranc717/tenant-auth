
package org.illinicloud.idp.tenant.authn.provider;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import edu.internet2.middleware.shibboleth.idp.profile.IdPProfileHandlerManager;
import org.illinicloud.idp.tenant.authn.TenantUsernamePasswordLoginHandler;
import org.ldaptive.*;
import org.ldaptive.auth.*;
import org.ldaptive.pool.PooledConnectionFactory;
import org.opensaml.saml2.core.AuthnContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class TenantAttributeResolverServlet extends HttpServlet {

    /** Serial version UID. */
    private static final long serialVersionUID = -572799841125956990L;

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(TenantAttributeResolverServlet.class);

    /** TenantUserNamePasswordLoginHandler is the bean in which the ldap connection pools are managed */
    private TenantUsernamePasswordLoginHandler loginHandler;

    /** Domain Authenticator */
    private Authenticator auth;

    /** LdapEntry that results from lookup against ldap */
    LdapEntry ldapEntry;

    /** {@inheritDoc} */
    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        ServletContext context = config.getServletContext();
        ApplicationContext appCtx = WebApplicationContextUtils.getWebApplicationContext(context);
        IdPProfileHandlerManager handlerManager = (IdPProfileHandlerManager)appCtx.getBean("shibboleth.HandlerManager");
        loginHandler = (TenantUsernamePasswordLoginHandler) handlerManager.getLoginHandlers().get(AuthnContext.PPT_AUTHN_CTX);

    }

    /** {@inheritDoc} */
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException,
            IOException {

        String principal = request.getParameter("userPrincipalName");
        String user ="";
        String domain = "";
        Map<String, Object> jsonString = new HashMap<String,Object>();

        if (principal != null) {
            int indexAmp = principal.indexOf('@');
            if (indexAmp > 0) {
                user = principal.substring(0, indexAmp);
                if (indexAmp != (principal.length() - 1)) {
                    domain = principal.substring(indexAmp + 1);
                }
            }
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

            List<Map<String,Object>> attrs = new ArrayList<Map<String,Object>>();
            try {
                performLdapSearch(user);
                if (ldapEntry == null) {
                  log.error("The user {} doesn't exist in the domain {}",user,domain);
                  String json = new Gson().toJson("The user " + user + " does not exist in the domain " + domain);
                  response.setContentType("application/json");
                  response.setCharacterEncoding("UTF-8");
                  response.setStatus(HttpServletResponse.SC_NOT_FOUND);
                  response.getWriter().write(json);
                  return;
                }


                for (final LdapAttribute ldapAttribute : ldapEntry.getAttributes()) {
                    if(( ldapAttribute.getName().contains("msExch") ) ||
                        (ldapAttribute.getName().contains("objectGUID")) ||
                        (ldapAttribute.getName().contains("objectSid")) ||
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
                                jsonString.put("attributeValue",ldapAttribute.getStringValue());
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

                    Map<String,List> ldapAttributes = new HashMap<String, List>();
                    ldapAttributes.put("LDAPAttributes",attrs);
                    Gson gson = new GsonBuilder().disableHtmlEscaping().create();
                    String json = gson.toJson(ldapAttributes);
                    log.trace("Here is the json " + json);
                    response.setContentType("application/json");
                    response.setCharacterEncoding("UTF-8");
                    response.getWriter().write(json);

            } catch (LdapException e) {
                log.error(e.getMessage());
                String json = new Gson().toJson("An error occurred while fulfilling the request");
                response.setContentType("application/json");
                response.setCharacterEncoding("UTF-8");
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                response.getWriter().write(json);
            }
        }
    }

    protected void performLdapSearch(String user) throws LdapException {

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

        }
    }
}
