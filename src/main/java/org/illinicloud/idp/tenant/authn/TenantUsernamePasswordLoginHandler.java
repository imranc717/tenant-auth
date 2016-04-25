package org.illinicloud.idp.tenant.authn;

import edu.internet2.middleware.shibboleth.idp.authn.provider.AbstractLoginHandler;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.IOException;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.ldaptive.auth.Authenticator;

/**
 * Authenticate a username and password against a JAAS Source while leveraging connection pooling.
 * Upon initialization, the factory class will set the pooled authenticators for each approved LEA
 * This login handler creates a {@link javax.security.auth.Subject} and binds it to the request as described in the
 * {@link edu.internet2.middleware.shibboleth.idp.authn.LoginHandler} documentation. If the JAAS module does not create
 * a principal for the user a {@link edu.internet2.middleware.shibboleth.idp.authn.UsernamePrincipal} is created, using
 * the entered username. If the <code>storeCredentialsInSubject</code> init parameter of the authentication servlet is
 * set to true a UsernamePasswordCredential is created, based on the entered username and password, and stored
 * in the Subject's private credentials.
 */

public class TenantUsernamePasswordLoginHandler extends AbstractLoginHandler {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(TenantUsernamePasswordLoginHandler.class);

    /** The context-relative path of the servlet used to perform authentication. */
    private String authenticationServletPath;

    /** Map containing all LEA ldap pools */
    private Map<String,Authenticator> tenantPools;

    /** Encryptor used to decrypt bind credentials */
    private StandardPBEStringEncryptor encryptor;


    /**
     * Constructor.
     *
     * @param servletPath context-relative path to the authentication servlet, may start with "/"
     */
    public TenantUsernamePasswordLoginHandler(String servletPath) throws Exception  {
        super();
        setSupportsPassive(false);
        setSupportsForceAuthentication(true);
        authenticationServletPath = servletPath;

    }

    public Map<String,Authenticator> getTenantPools()
    {
        return tenantPools;
    }

    public void setTenantPools(Map<String, Authenticator> pools)
    {
        tenantPools = pools;
    }

    public void setEncryptor(StandardPBEStringEncryptor enc) { encryptor = enc;}

    public StandardPBEStringEncryptor getEncryptor()
    {
        return encryptor;
    }

    /** {@inheritDoc} */
    public void login(final HttpServletRequest httpRequest, final HttpServletResponse httpResponse) {
        // forward control to the servlet.
        try {
            String authnServletUrl = HttpServletHelper.getContextRelativeUrl(httpRequest, authenticationServletPath)
                    .buildURL();
            log.debug("Redirecting to {}", authnServletUrl);
            httpResponse.sendRedirect(authnServletUrl);
            return;
        } catch (IOException ex) {
            log.error("Unable to redirect to authentication servlet.", ex);
        }

    }



}
