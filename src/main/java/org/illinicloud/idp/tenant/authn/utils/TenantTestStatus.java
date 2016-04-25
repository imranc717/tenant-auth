package org.illinicloud.idp.tenant.authn.utils;


public class TenantTestStatus {

    private boolean success;
    private String description;
    private String cert;

    public void setSuccess(boolean outcome) {
        success = outcome;
    }

    public boolean getSuccess() {
        return success;
    }

    public void setDescription(String cause) {
        description = cause;
    }

    public String getDescription() {
        return description;
    }

    public void setCert(String pem) {
        cert = pem;
    }

    public String getCert() {
        return cert;
    }
}
