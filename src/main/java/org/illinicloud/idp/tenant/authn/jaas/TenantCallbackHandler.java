package org.illinicloud.idp.tenant.authn.jaas;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.security.auth.callback.*;
import java.io.IOException;

public class TenantCallbackHandler implements CallbackHandler {

    /**
     * Log for this class.
     */
    protected final Log log = LogFactory.getLog(TenantCallbackHandler.class);

    private String username = null;
    private char[] password = null;
    private String orgDn = null;

    public TenantCallbackHandler(String username, char[] password, String orgDn) {
        this.username = username;
        this.password = password;
        this.orgDn = orgDn;
    }

    public TenantCallbackHandler(CallbackHandler callbackHandler) {
        Callback[] callbacks = new Callback[2];
        callbacks[0] = new NameCallback("Username");
        callbacks[1] = new PasswordCallback("Password", false);

        try {
            callbackHandler.handle(callbacks);
        } catch (IOException e) {
            log.error("Error initializing login module - IOException from callbackHandler!", e);
        } catch (UnsupportedCallbackException e) {
            log.error("Error initializing login module - UnsupportedCallbackException from callbackHandler!");
        }

        String userNamePlusOrgDn = ((NameCallback) callbacks[0]).getName();
        int indexAmp = userNamePlusOrgDn.indexOf('@');
        if (indexAmp > 0) {
            this.username = userNamePlusOrgDn.substring(0, indexAmp);
            if (indexAmp != (userNamePlusOrgDn.length() - 1)) {
                this.orgDn = userNamePlusOrgDn.substring(indexAmp + 1);
            }
        } else if (indexAmp == 0) {
            if (indexAmp != (userNamePlusOrgDn.length() - 1)) {
                this.orgDn = userNamePlusOrgDn.substring(indexAmp + 1);
            }
        } else {
            this.username = userNamePlusOrgDn;
        }
        this.password = ((PasswordCallback) callbacks[1]).getPassword();
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (Callback callback : callbacks) {
            if (callback instanceof NameCallback) {
                NameCallback nameCallback = (NameCallback) callback;
                nameCallback.setName(username);
            } else if (callback instanceof PasswordCallback) {
                PasswordCallback passwordCallback = (PasswordCallback) callback;
                passwordCallback.setPassword(password);
            } else if (callback instanceof TextInputCallback) {
                TextInputCallback textInputCallback = (TextInputCallback) callback;
                textInputCallback.setText(orgDn);
            } else {
                throw new UnsupportedCallbackException(callback, "The submitted Callback is unsupported");
            }
        }

    }
}
