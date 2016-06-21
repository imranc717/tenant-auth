package org.illinicloud.idp.tenant.authn.utils;


public class ConnectionInfo {

    private String host;
    private int port;
    private String account;
    private String password;
    private String baseDN;
    private String action;
    public static final String CONNECTION = "testConnection";
    public static final String IDP = "testIDPAccount";
    public static final String SP = "testSPAccount";


    public void setHost(String hostName) {
        host = hostName;
    }

    public String getHost() {
        return host;
    }

    public void setPort(int connPort) {
        port = connPort;
    }

    public int getPort() {
        return port;
    }

    public void setAccount(String id) {
        account = id;

    }

    public String getAccount() {
        return account;
    }

    public void setPassword(String pass) {
        password = pass;
    }

    public String getPassword() {
        return password;
    }

    public void setBaseDN(String searchBase) {
        baseDN = searchBase;
    }

    public String getBaseDN() {
        return baseDN;
    }

    public void setAction(String requestedAction) { action = requestedAction ;}

    public String getAction() { return action; }

}


