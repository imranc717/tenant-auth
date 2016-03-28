package org.illinicloud.idp.tenant.authn.provider;


import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginException;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import edu.internet2.middleware.shibboleth.idp.authn.provider.UsernamePasswordCredential;
import org.illinicloud.idp.tenant.authn.TenantUsernamePasswordLoginHandler;
import org.ldaptive.auth.Authenticator;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.xml.util.DatatypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import edu.internet2.middleware.shibboleth.idp.profile.IdPProfileHandlerManager;

import edu.internet2.middleware.shibboleth.idp.authn.LoginHandler;
import edu.internet2.middleware.shibboleth.idp.authn.UsernamePrincipal;
import org.springframework.context.ApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;
import edu.internet2.middleware.shibboleth.idp.authn.provider.UsernamePasswordLoginServlet;

/**
 * This Servlet authenticates a user via JAAS. The user's credential is always added to the returned {@link Subject} as
 * a {@link UsernamePasswordCredential} within the subject's private credentials.
 *
 * By default, this Servlet assumes that the authentication method
 * <code>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</code> to be returned to the authentication
 * engine. This can be override by setting the servlet configuration parameter <code>authnMethod</code>.
 */

public class TenantUsernamePasswordLoginServlet extends UsernamePasswordLoginServlet{

    /** Serial version UID. */
    private static final long serialVersionUID = -2038493216591713099L;

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(TenantUsernamePasswordLoginServlet.class);

    /** The authentication method returned to the authentication engine. */
    private String authenticationMethod;

    /** TenantUserNamePasswordLoginHandler instance */
    private TenantUsernamePasswordLoginHandler loginHandler;

    /** This is the login module to be specified in the Configuration object */
    private String loginModule = "org.illinicloud.idp.tenant.authn.jaas.TenantLdapLoginModule";

    /** init-param which can be passed to the servlet to override the default Login Module. */
    private final String loginModuleInitParam = "loginModule";


    /** {@inheritDoc} */
    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        if (getInitParameter(loginModuleInitParam) != null) {
            loginModule = getInitParameter(loginModuleInitParam);
        }

        String method =
                DatatypeHelper.safeTrimOrNullString(config.getInitParameter(LoginHandler.AUTHENTICATION_METHOD_KEY));
        if (method != null) {
            authenticationMethod = method;
        } else {
            authenticationMethod = AuthnContext.PPT_AUTHN_CTX;
        }

        ServletContext context = config.getServletContext();
        ApplicationContext appCtx = WebApplicationContextUtils.getWebApplicationContext(context);
        IdPProfileHandlerManager handlerManager = (IdPProfileHandlerManager)appCtx.getBean("shibboleth.HandlerManager");
        loginHandler = (TenantUsernamePasswordLoginHandler) handlerManager.getLoginHandlers().get(authenticationMethod);

    }



    /**
     * Authenticate a username and password against JAAS. If authentication succeeds the name of the first principal, or
     * the username if that is empty, and the subject are placed into the request in their respective attributes.
     *
     * @param request current authentication request
     * @param username the principal name of the user to be authenticated
     * @param password the password of the user to be authenticated
     *
     * @throws LoginException thrown if there is a problem authenticating the user
     */

    @Override
    protected void authenticateUser(HttpServletRequest request, String username, String password) throws LoginException {
        try {

            log.debug("Attempting to authenticate user {}", username);

            SimpleCallbackHandler cbh = new SimpleCallbackHandler(username, password);
            String orgDn = null;
            Map <String, Authenticator> options = new HashMap<String, Authenticator>();

            int indexAmp = username.indexOf('@');
            if (indexAmp > 0) {
                if (indexAmp != (username.length() - 1)) {
                    orgDn = username.substring(indexAmp + 1);
                }
            } else if (indexAmp == 0) {
                if (indexAmp != (username.length() - 1)) {
                    orgDn = username.substring(indexAmp + 1);
                }
            }
            log.debug("The user organization is {}", orgDn);
            options.put(orgDn,loginHandler.getTenantPools().get(orgDn));
            Configuration config = new TenantLoginConfiguration(loginModule,options);
            javax.security.auth.login.LoginContext jaasLoginCtx = new javax.security.auth.login.LoginContext(
                    "name",null,cbh,config);

            jaasLoginCtx.login();
            log.debug("Successfully authenticated user {}", username);

            Subject loginSubject = jaasLoginCtx.getSubject();

            Set<Principal> principals = loginSubject.getPrincipals();

            principals.add(new UsernamePrincipal(username));

            Set<Object> publicCredentials = loginSubject.getPublicCredentials();

            Set<Object> privateCredentials = loginSubject.getPrivateCredentials();
            privateCredentials.add(new UsernamePasswordCredential(username, password));

            Subject userSubject = new Subject(false, principals, publicCredentials, privateCredentials);
            request.setAttribute(LoginHandler.SUBJECT_KEY, userSubject);
            request.setAttribute(LoginHandler.AUTHENTICATION_METHOD_KEY, authenticationMethod);
        } catch (LoginException e) {
            log.debug("User authentication for " + username + " failed", e);
            throw e;
        } catch (Throwable e) {
            log.debug("User authentication for " + username + " failed", e);
            throw new LoginException("unknown authentication error");
        }
    }



}
