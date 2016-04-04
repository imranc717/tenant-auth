package org.illinicloud.idp.tenant.authn.resolver;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import edu.internet2.middleware.shibboleth.common.attribute.BaseAttribute;
import edu.internet2.middleware.shibboleth.common.attribute.provider.BasicAttribute;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolutionException;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.provider.ShibbolethResolutionContext;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.provider.dataConnector.BaseDataConnector;
import edu.internet2.middleware.shibboleth.common.session.Session;
import org.ldaptive.LdapAttribute;
import org.ldaptive.LdapEntry;
import org.ldaptive.jaas.LdapPrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.HttpsURLConnection;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Type;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;


public class TenantAttributeResolver extends BaseDataConnector {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(TenantAttributeResolver.class);

    /** URL for tenant attribute service endpoint */
    private String url;

    /** Constant that represents query parameter that is passed in */
    private static final String FQDN = "fqdn";


    public TenantAttributeResolver(String address) {
        super();
        url = address;
        log.debug("The url set is {}", address);
    }

    public Map<String, BaseAttribute> resolve(ShibbolethResolutionContext resolutionContext) throws AttributeResolutionException {

        String username = "";
        final URL targetURL;

        /** Determine if an LDAPPrincipal already exists in the user session.
         *  If one does exist, it means the user was authenticated locally and
         *  no attribute lookup is required.
         *  Returns an empty map (not null) back to resolution engine.
         */

        final Session userSession = resolutionContext.getAttributeRequestContext().getUserSession();
        if (userSession == null) {
            log.error("No user session available, unable to extract principal information");
            return Collections.emptyMap();
        }


        Set<LdapPrincipal> ldapPrincipals = userSession.getSubject().getPrincipals(LdapPrincipal.class);
        if (ldapPrincipals.size() > 0) {
            log.info("An ldapPrincipal exists in the user session, no need to lookup attributes again");
            return Collections.emptyMap();
        }

        log.debug("Retrieving Connector dependencies");
        Collection<Object> values = getValuesFromAttributeDependency(resolutionContext,FQDN);
        Iterator itr = values.iterator();
        while (itr.hasNext()) {
            username = (String) itr.next();
        }

        if (username.equals("")) {
            log.error("The dependency attribute fqdn does not exist");
            throw new AttributeResolutionException("The dependency attribute fqdn does not exist");
        }

        String query = "?userPrincipalName="+username;

        try {
            targetURL = new URL(url + query);
            log.debug("The target url is {}", targetURL.toString());
        } catch (MalformedURLException e) {
            log.error("The url parameter specified in the Data Connector config is malformed");
            return Collections.emptyMap();
            /*throw new AttributeResolutionException(e.getMessage());*/
        }

        String jsonString = connect(targetURL);

        LdapPrincipal ldapPrincipal = createPrincipal(jsonString,username);
        resolutionContext.getAttributeRequestContext().getUserSession().getSubject().getPrincipals().add(ldapPrincipal);

        Map<String, BaseAttribute> result = new HashMap<String, BaseAttribute>();
        BasicAttribute userLdapAttributes = new BasicAttribute("userLdapAttributes");
        userLdapAttributes.getValues().add(jsonString);

        result.put("userLdapAttributes",userLdapAttributes);

        return result;
    }

    protected String connect(URL targetURL) throws AttributeResolutionException {

        HttpsURLConnection connection = null;
        String jsonString = "";

        try {
            log.debug("Attempting to connect to {}",targetURL.toString());
            connection = (HttpsURLConnection) targetURL.openConnection();
            connection.setRequestMethod("GET");
            connection.setReadTimeout(5000);
            log.debug("Open connection to {}", targetURL.toString());
            connection.connect();

            int code = connection.getResponseCode();
            if (code == HttpServletResponse.SC_OK) {
                final BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                StringBuilder response = new StringBuilder();
                String line;
                while((line = br.readLine()) != null) {
                    response.append(line).append('\r');
                }
                br.close();
                jsonString = response.toString();
                log.trace("The attribute service response {}", jsonString);

            } else {
                log.error("The request to url {} produced no results",targetURL.toString());
                jsonString = "Not found";
            }

        } catch (IOException e) {
            log.error("Error making connection to servlet");
            log.error(e.getMessage());
            throw new AttributeResolutionException(e.getMessage());
        } finally {
            if (connection != null)
                connection.disconnect();
        }

        return jsonString;
    }

    protected LdapPrincipal createPrincipal(String json, String username) {

        Gson gson = new Gson();
        Type tokenType = new TypeToken<Map<String,List<Map<String,Object>>>>(){}.getType();
        Map<String,List<Map<String,Object>>> ldapEntry = gson.fromJson(json, tokenType);
        List attributes = ldapEntry.get("LDAPAttributes");
        Map<String,Object> attrs;
        List<LdapAttribute> ldapAttributes = new ArrayList<LdapAttribute>();
        Iterator it = attributes.iterator();

        while (it.hasNext()) {
            attrs = (Map <String,Object>)it.next();
            LdapAttribute ldapAttribute = new LdapAttribute((String) attrs.get("attributeName"));
            if (attrs.get("isMultiValue").equals("false")) {
                if (attrs.get("isBinary").equals("false"))
                    ldapAttribute.addStringValue((String) attrs.get("attributeValue"));
                else
                    ldapAttribute.addBinaryValue((byte[]) attrs.get("attributeValue"));
            } else {
                if (attrs.get("isBinary").equals("false"))
                    ldapAttribute.addStringValues((Collection<String>) attrs.get("attributeValue"));
                else
                    ldapAttribute.addBinaryValues((Collection<byte[]>) attrs.get("attributeValue"));
            }
            ldapAttributes.add(ldapAttribute);
        }

        LdapEntry entry = new LdapEntry();
        entry.addAttributes(ldapAttributes);
        LdapPrincipal ldapPrincipal = new LdapPrincipal(username,entry);
        return ldapPrincipal;
    }

    /** {@inheritDoc} */
    public void validate() throws AttributeResolutionException {

    }
}
