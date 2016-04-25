package org.illinicloud.idp.tenant.authn.utils;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import java.util.Map;


public class TenantLoginConfiguration extends Configuration{

    private Map<String, ?> options;
    private String loginModuleName;

    public TenantLoginConfiguration()
    {
    }

    public TenantLoginConfiguration(final String loginModuleName, final Map<String, ?> options)
    {
        this.loginModuleName = loginModuleName;
        this.options = options;
    }

    @Override
    public AppConfigurationEntry[] getAppConfigurationEntry(String name)
    {
        AppConfigurationEntry entry = new AppConfigurationEntry(loginModuleName,
                AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                options);
        return new AppConfigurationEntry[] { entry };
    }
}
