package org.illinicloud.idp.tenant.authn.provider;


import com.google.gson.Gson;
import edu.internet2.middleware.shibboleth.idp.profile.IdPProfileHandlerManager;
import org.bouncycastle.openssl.PEMWriter;
import org.illinicloud.idp.tenant.authn.TenantUsernamePasswordLoginHandler;
import org.illinicloud.idp.tenant.authn.utils.ConnectionInfo;
import org.illinicloud.idp.tenant.authn.utils.TenantTestStatus;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.ldaptive.*;
import org.ldaptive.ssl.*;
import org.opensaml.saml2.core.AuthnContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.StringWriter;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class TenantTestServlet extends HttpServlet {

    /** Serial version UID. */
    private static final long serialVersionUID = -823466990017365886L;

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(TenantTestServlet.class);

    /** TenantUserNamePasswordLoginHandler to decrypt credentials for bind account */
    private TenantUsernamePasswordLoginHandler loginHandler;

    /** Encryptor used to decrypt bind credentials */
    private StandardPBEStringEncryptor encryptor;

    private static final String CONNECTION = "testConnection";

    /** {@inheritDoc} */
    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        ServletContext context = config.getServletContext();
        ApplicationContext appCtx = WebApplicationContextUtils.getWebApplicationContext(context);
        IdPProfileHandlerManager handlerManager = (IdPProfileHandlerManager)appCtx.getBean("shibboleth.HandlerManager");
        loginHandler = (TenantUsernamePasswordLoginHandler) handlerManager.getLoginHandlers().get(AuthnContext.PPT_AUTHN_CTX);
        encryptor = loginHandler.getEncryptor();

    }

    protected void testConnection(HttpServletResponse response, ConnectionInfo connectionInfo)
            throws ServletException, IOException {

        Gson gson = new Gson();
        try {

            Integer timeout = 5000;
            SslConfig sslConfig = new SslConfig();
            SavingTrustManager savingTrustManager = new SavingTrustManager(new AllowAnyTrustManager());

            if (connectionInfo.getAction().equalsIgnoreCase(CONNECTION)) {
                sslConfig.setTrustManagers(new TrustManager[] {savingTrustManager});
            } else {
                KeyStoreCredentialConfig credentialConfig = new KeyStoreCredentialConfig();
                credentialConfig.setTrustStore("classpath:/cacerts");
                credentialConfig.setTrustStorePassword("changeit");
                sslConfig.setCredentialConfig(credentialConfig);
            }

            String ldapURL = "ldap://" + connectionInfo.getHost() + ":" + connectionInfo.getPort();
            ConnectionConfig connectionConfig = new ConnectionConfig();
            connectionConfig.setSslConfig(sslConfig);
            connectionConfig.setUseSSL(true);
            connectionConfig.setConnectTimeout(timeout.longValue());
            connectionConfig.setResponseTimeout(timeout.longValue());
            connectionConfig.setLdapUrl(ldapURL);

            if (!connectionInfo.getAction().equalsIgnoreCase(CONNECTION)) {
                String pwd = encryptor.decrypt(connectionInfo.getPassword());
                connectionConfig.setConnectionInitializer(new BindConnectionInitializer(connectionInfo.getAccount(), new Credential(pwd)));
            }

            DefaultConnectionFactory cf = new DefaultConnectionFactory(connectionConfig);
            Connection connection = cf.getConnection();
            connection.open();

            TenantTestStatus status = new TenantTestStatus();
            if (connection.isOpen()) {
                status.setSuccess(true);
                status.setDescription("success");
                connection.close();
                if (connectionInfo.getAction().equalsIgnoreCase(CONNECTION)) {
                    if (savingTrustManager.certChain != null) {
                        log.debug("The chain exists");
                        X509Certificate[] chain = savingTrustManager.certChain;

                        for (int i = 0; i < chain.length; i++) {
                            X509Certificate cert = chain[i];
                            log.debug("Chain element " + i + " certificate Subject is " + cert.getSubjectDN());
                            log.debug("Chain element " + i + " certificate Issuer is " + cert.getIssuerDN());
                        }

                        StringWriter sw = new StringWriter();
                        X509Certificate certificate = chain[(chain.length - 1)];
                        PEMWriter pw = new PEMWriter(sw);
                        pw.writeObject(certificate);
                        pw.flush();
                        pw.close();
                        status.setCert(sw.toString());
                    }
                }
            } else {
                status.setSuccess(false);
                status.setDescription("Unable to establish an ldap connection to " + connectionInfo.getHost());
            }

            response.getOutputStream().print(gson.toJson(status));
            response.getOutputStream().flush();
        } catch (Exception ex) {
            log.error(ex.getMessage());
            TenantTestStatus status = new TenantTestStatus();
            status.setSuccess(false);
            status.setDescription(ex.getMessage());
            response.getOutputStream().print(gson.toJson(status));
            response.getOutputStream().flush();
        }
    }



    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType("application/json");
        Gson gson = new Gson();

        try {
            StringBuilder sb = new StringBuilder();
            String s;

            while ((s = request.getReader().readLine()) != null) {
                sb.append(s);
            }

            ConnectionInfo connectionInfo = gson.fromJson(sb.toString(), ConnectionInfo.class);
            testConnection(response, connectionInfo);


            /*processRequest(request, response);*/
        } catch (Exception ex) {
            log.error(ex.getMessage());
            TenantTestStatus status = new TenantTestStatus();
            status.setSuccess(false);
            status.setDescription(ex.getMessage());
            response.getOutputStream().print(gson.toJson(status));
            response.getOutputStream().flush();
        }
    }

    private static class SavingTrustManager implements X509TrustManager {

        private final X509TrustManager tm;
        private X509Certificate[] certChain;

        SavingTrustManager(X509TrustManager tm) {
            this.tm = tm;
        }

        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }

        public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {}

        public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            certChain = chain;
            tm.checkServerTrusted(chain, authType);
        }
    }

}
