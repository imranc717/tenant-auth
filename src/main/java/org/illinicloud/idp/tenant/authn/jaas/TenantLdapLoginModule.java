package org.illinicloud.idp.tenant.authn.jaas;

import org.ldaptive.LdapException;
import org.ldaptive.ReturnAttributes;
import org.ldaptive.auth.AuthenticationRequest;
import org.ldaptive.auth.AuthenticationResponse;
import org.ldaptive.auth.Authenticator;
import org.ldaptive.jaas.*;
import org.ldaptive.Credential;
import org.ldaptive.LdapEntry;

import javax.security.auth.Subject;
import javax.security.auth.callback.*;
import javax.security.auth.login.LoginException;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class TenantLdapLoginModule extends AbstractLoginModule {

    /** User attribute to add to role data. */
    private String userRoleAttribute = ReturnAttributes.ALL_USER.value()[0];

    /** Authenticator to use against the LDAP. */
    private Authenticator auth;

    /** Authentication request to use for authentication. */
    private AuthenticationRequest authRequest;

    /** Tenant organization domain name used to lookup pool */
    private String tenantOrgDn = null;
    private String username = null;
    private char[] password = null;

    @Override
    public void initialize( final Subject subject, final CallbackHandler callbackHandler,
                            final Map<String, ?> sharedState, final Map<String, ?> options) {

        setLdapPrincipal = true;
        setLdapCredential = true;

        TenantCallbackHandler tenantCallbackHandler = new TenantCallbackHandler(callbackHandler);
        this.callbackHandler = tenantCallbackHandler;

        Callback[] callbacks = new Callback[3];
        callbacks[0] = new TextInputCallback("OrgDn");
        callbacks[1] = new NameCallback("Username");
        callbacks[2] = new PasswordCallback("Password", false);

        try {
            tenantCallbackHandler.handle(callbacks);
        } catch (IOException e) {
            logger.error("Error initializing login module - IOException from callbackHandler!", e);
        } catch (UnsupportedCallbackException e) {
            logger.error("Error initializing login module - UnsupportedCallbackException from callbackHandler!", e);
        }

        username = ((NameCallback) callbacks[1]).getName();
        tenantOrgDn = ((TextInputCallback) callbacks[0]).getText();
        password = ((PasswordCallback) callbacks[2]).getPassword();

        for (String key : options.keySet()) {
            if (tenantOrgDn.equalsIgnoreCase(key)) {
                auth = (Authenticator) options.get(key);
            }
        }

        Credential credential = new Credential(password);
        authRequest = new AuthenticationRequest(username, credential, userRoleAttribute);
        logger.debug("Initializing login module for user <" + this.username + "> and organization dn <" + this.tenantOrgDn + ">.");
        super.initialize(subject, callbackHandler, sharedState, new HashMap<String, String>());

    }

    @Override
    public boolean login() throws LoginException {
        try {
            AuthenticationResponse response = auth.authenticate(authRequest);
            LdapEntry entry = null;
            if (response.getResult()) {
                entry = response.getLdapEntry();
                if (entry != null) {
                    roles.addAll(LdapRole.toRoles(entry));
                    if (defaultRole != null && !defaultRole.isEmpty()) {
                        roles.addAll(defaultRole);
                    }
                }
                loginSuccess = true;
            } else {
                loginSuccess = false;
            }

            if (!loginSuccess) {
                logger.debug("Authentication failed: " + response);
                throw new LoginException("Authentication failed: " + response);
            } else {
                if (setLdapPrincipal) {
                    principals.add(new LdapPrincipal(username, entry));
                }

                final String loginDn = response.getResolvedDn();
                if (loginDn != null && setLdapDnPrincipal) {
                    principals.add(new LdapDnPrincipal(loginDn, entry));
                }

                if (setLdapCredential) {
                    credentials.add(new LdapCredential(password));
                }

            }
        } catch (LdapException e) {
            logger.debug("Error occurred attempting authentication", e);
            loginSuccess = false;
            throw new LoginException(e != null ? e.getMessage() : "Authentication Error");
        }

        return true;
    }

    protected boolean login(final NameCallback nameCb, final PasswordCallback passCb) throws LoginException {
        return true;
    }

}
