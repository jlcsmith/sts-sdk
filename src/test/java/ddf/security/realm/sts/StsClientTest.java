package ddf.security.realm.sts;

import static org.hamcrest.core.IsNull.notNullValue;
import static org.junit.Assert.assertThat;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
//import static org.junit.Assert.assertThat;
//import static org.hamcrest.Matchers.notNullValue;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLStreamException;

import org.apache.commons.collections.MapUtils;
import org.apache.cxf.Bus;
import org.apache.cxf.BusFactory;
import org.apache.cxf.bus.CXFBusFactory;
import org.apache.cxf.bus.spring.SpringBusFactory;
import org.apache.cxf.staxutils.W3CDOMStreamWriter;
import org.apache.cxf.ws.security.SecurityConstants;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.apache.cxf.ws.security.trust.STSClient;
import org.apache.cxf.ws.security.trust.STSUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.codice.ddf.security.common.Security;
import org.junit.experimental.theories.internal.ParameterizedAssertionError;
import java.net.URISyntaxException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.DOMImplementation;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSSerializer;
import org.apache.wss4j.dom.WSConstants;
import javax.xml.parsers.DocumentBuilder;
import org.apache.wss4j.dom.message.token.UsernameToken;
import javax.xml.parsers.DocumentBuilderFactory;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import ddf.security.PropertiesLoader;

public class StsClientTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(StsClientTest.class);

    private static final String SAML2_ASSERTION_TYPE =
            "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";

    private static final String STS_ENDPOINT_ADDRESS =
            "https://localhost:8993/services/SecurityTokenService?wsdl";

    private static final String BEARER_ASSERTION =
            "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer";

    private static final String SERVICE_NAME =
            "{http://docs.oasis-open.org/ws-sx/ws-trust/200512/}SecurityTokenService";

    private static final String ENDPOINT_NAME =
            "{http://docs.oasis-open.org/ws-sx/ws-trust/200512/}STS_Port";

    private static final String ADDRESSING_NAMESPACE = "http://www.w3.org/2005/08/addressing";

    private static final String[] CLAIMS =
            new String[] {"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier",
                    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
                    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
                    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
                    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/role"};

    protected Bus bus;

    @Before
    public void setup() throws URISyntaxException {
        bus = getBus();
        System.setProperty("javax.net.ssl.keyStoreType", "JKS");
        System.setProperty("javax.net.ssl.keyStore",
                getClass().getResource("/serverKeystore.jks")
                        .toURI()
                        .getPath());
        System.setProperty("javax.net.ssl.keyStorePassword", "changeit");
        System.setProperty("javax.net.ssl.trustStoreType", "JKS");
        System.setProperty("javax.net.ssl.trustStore",
                getClass().getResource("/serverTruststore.jks")
                        .toURI()
                        .getPath());
        System.setProperty("javax.net.ssl.trustStorePassword", "changeit");
       // System.setProperty("ddf.home", "/ddf/home");
        System.setProperty("org.codice.ddf.system.hostname", "localhost");
    }


    @Test
    public void testGetToken() {

        SecurityToken token = null;
        try {
            LOGGER.info("Retrieving security token...");
            token = requestSecurityToken();
            LOGGER.info("token retrieved {}", token.getId());
        }catch (Exception e ){
            LOGGER.error("Unable to get security token", e);
        }
        assertThat(token,notNullValue());

    }


    protected Bus getBus() {
        BusFactory bf = new CXFBusFactory();
        Bus setBus = bf.createBus();
        SpringBusFactory.setDefaultBus(setBus);
        SpringBusFactory.setThreadDefaultBus(setBus);

        return setBus;
    }

    private STSClient configureBaseStsClient() {
        STSClient stsClient = new STSClient(bus);
        String stsAddress = STS_ENDPOINT_ADDRESS;
        String stsServiceName = SERVICE_NAME;
        String stsEndpointName = ENDPOINT_NAME;

        if (stsAddress != null) {
            LOGGER.debug("Setting WSDL location on STSClient: " + stsAddress);
            stsClient.setWsdlLocation(stsAddress);
        }

        if (stsServiceName != null) {
            LOGGER.debug("Setting service name on STSClient: " + stsServiceName);
            stsClient.setServiceName(stsServiceName);
        }

        if (stsEndpointName != null) {
            LOGGER.debug("Setting endpoint name on STSClient: " + stsEndpointName);
            stsClient.setEndpointName(stsEndpointName);
        }

        LOGGER.debug("Setting addressing namespace on STSClient: " + ADDRESSING_NAMESPACE);
        stsClient.setAddressingNamespace(ADDRESSING_NAMESPACE);

        return stsClient;
    }

    /**
     * Helper method to setup STS Client.
     *
     * @param stsClient
     */
    private void addStsProperties(STSClient stsClient) {
        Map<String, Object> map = new HashMap<>();

        String signaturePropertiesPath = "signature.properties";
        if (signaturePropertiesPath != null && !signaturePropertiesPath.isEmpty()) {
            LOGGER.debug("Setting signature properties on STSClient: " + signaturePropertiesPath);
            Properties signatureProperties =
                    PropertiesLoader.loadProperties(signaturePropertiesPath);
            if(MapUtils.isEmpty(signatureProperties)) {
                throw new IllegalArgumentException("Properties are empty");
            }
            map.put(SecurityConstants.SIGNATURE_PROPERTIES, signatureProperties);
        }

        String encryptionPropertiesPath = "encryption.properties";

        if (encryptionPropertiesPath != null && !encryptionPropertiesPath.isEmpty()) {
            LOGGER.debug("Setting encryption properties on STSClient: " + encryptionPropertiesPath);
            Properties encryptionProperties = PropertiesLoader.loadProperties(
                    encryptionPropertiesPath);
            if(MapUtils.isEmpty(encryptionProperties)) {
                throw new IllegalArgumentException("Properties are empty");
            }
            map.put(SecurityConstants.ENCRYPT_PROPERTIES, encryptionProperties);
        }

        String stsPropertiesPath = "signature.properties";
        if (stsPropertiesPath != null && !stsPropertiesPath.isEmpty()) {
            LOGGER.debug("Setting sts properties on STSClient: " + stsPropertiesPath);
            Properties stsProperties = PropertiesLoader.loadProperties(stsPropertiesPath);
            if(MapUtils.isEmpty(stsProperties)) {
                throw new IllegalArgumentException("Properties are empty");
            }
            map.put(SecurityConstants.STS_TOKEN_PROPERTIES, stsProperties);
        }

        LOGGER.debug("Setting callback handler on STSClient");

        LOGGER.debug("Setting STS TOKEN USE CERT FOR KEY INFO to \"true\"");
        map.put(SecurityConstants.STS_TOKEN_USE_CERT_FOR_KEYINFO, "true");

        LOGGER.debug("Adding in realm information to the STSClient");
        map.put("CLIENT_REALM", "DDF");

        stsClient.setProperties(map);
    }

    private String getFormattedXml(Node node) {
        Document document = node.getOwnerDocument()
                .getImplementation()
                .createDocument("", "fake", null);
        Element copy = (Element) document.importNode(node, true);
        document.importNode(node, false);
        document.removeChild(document.getDocumentElement());
        document.appendChild(copy);
        DOMImplementation domImpl = document.getImplementation();
        DOMImplementationLS domImplLs = (DOMImplementationLS) domImpl.getFeature("LS", "3.0");
        if (null != domImplLs) {
            LSSerializer serializer = domImplLs.createLSSerializer();
            serializer.getDomConfig()
                    .setParameter("format-pretty-print", true);
            return serializer.writeToString(document);
        } else {
            return "";
        }
    }

    private void setClaimsOnStsClient(STSClient stsClient, Element claimsElement) {
        if (claimsElement != null) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug(" Setting STS claims to:\n" + this.getFormattedXml(claimsElement));
            }

            stsClient.setClaims(claimsElement);
        }
    }

    protected Element createClaimsElement() {
        Element claimsElement = null;
        List<String> claims = new ArrayList<>();
        claims.addAll(Arrays.asList(CLAIMS));
        // @formatter:off

/**  TODO - is this needed?
 *
 *
        if (contextPolicyManager != null) {
            Collection<ContextPolicy> contextPolicies = contextPolicyManager.getAllContextPolicies();
            Set<String> attributes = new LinkedHashSet<>();
            if (contextPolicies != null && contextPolicies.size() > 0) {
                for (ContextPolicy contextPolicy : contextPolicies) {
                    attributes.addAll(contextPolicy.getAllowedAttributeNames());
                }
            }

            if (attributes.size() > 0) {
                claims.addAll(attributes);
            }
        }
 */
        // @formatter:on

        if (claims.size() != 0) {
            W3CDOMStreamWriter writer = null;

            try {
                writer = new W3CDOMStreamWriter();

                writer.writeStartElement("wst", "Claims", STSUtils.WST_NS_05_12);
                writer.writeNamespace("wst", STSUtils.WST_NS_05_12);
                writer.writeNamespace("ic", "http://schemas.xmlsoap.org/ws/2005/05/identity");
                writer.writeAttribute("Dialect", "http://schemas.xmlsoap.org/ws/2005/05/identity");

                for (String claim : claims) {
                    LOGGER.trace("Claim: " + claim);
                    writer.writeStartElement("ic",
                            "ClaimType",
                            "http://schemas.xmlsoap.org/ws/2005/05/identity");
                    writer.writeAttribute("Uri", claim);
                    writer.writeAttribute("Optional", "true");
                    writer.writeEndElement();
                }

                writer.writeEndElement();

                claimsElement = writer.getDocument()
                        .getDocumentElement();
            } catch (XMLStreamException e) {
                String msg =
                        "Unable to create claims. Subjects will not have any attributes. Check STS Client configuration.";
                LOGGER.warn(msg, e);
                claimsElement = null;
            } finally {
                if (writer != null) {
                    try {
                        writer.close();
                    } catch (XMLStreamException ignore) {
                        //ignore
                    }
                }
            }

            if (LOGGER.isDebugEnabled()) {
                if (claimsElement != null) {
                    LOGGER.debug("\nClaims:\n" + getFormattedXml(claimsElement));
                }
            }
        } else {
            LOGGER.debug("There are no claims to process.");
            claimsElement = null;
        }

        return claimsElement;
    }

    private void logStsClientConfiguration(STSClient stsClient) {
        StringBuilder builder = new StringBuilder();

        builder.append("\nSTS Client configuration:\n");
        builder.append("STS WSDL location: " + stsClient.getWsdlLocation() + "\n");
        builder.append("STS service name: " + stsClient.getServiceQName() + "\n");
        builder.append("STS endpoint name: " + stsClient.getEndpointQName() + "\n");

        Map<String, Object> map = stsClient.getProperties();
        Set<Map.Entry<String, Object>> entries = map.entrySet();
        builder.append("\nSTS Client properties:\n");
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            builder.append("key: " + entry.getKey() + "; value: " + entry.getValue() + "\n");
        }

        LOGGER.info(builder.toString());
    }

    /**
     * Helper method to setup STS Client.
     */
    protected STSClient configureStsClient() {
        LOGGER.debug("Configuring the STS client.");

        STSClient stsClient = configureBaseStsClient();

        addStsProperties(stsClient);

        setClaimsOnStsClient(stsClient, createClaimsElement());

        if (LOGGER.isDebugEnabled()) {
            logStsClientConfiguration(stsClient);
        }

        return stsClient;
    }

    protected SecurityToken requestSecurityToken() throws ParserConfigurationException {

        return requestSecurityToken(createBasicTokenOnBehalfOf());
    }

    protected SecurityToken requestSecurityToken(Object authToken) {
        SecurityToken token = null;

        try {
            LOGGER.info("Requesting security token from STS at: " + STS_ENDPOINT_ADDRESS + ".");

            if (authToken != null) {
                LOGGER.info(
                        "Telling the STS to request a security token on behalf of the auth token");
                STSClient stsClient = configureStsClient();

                stsClient.setWsdlLocation(STS_ENDPOINT_ADDRESS);
                stsClient.setOnBehalfOf(authToken);
                stsClient.setTokenType(SAML2_ASSERTION_TYPE);
                stsClient.setKeyType(BEARER_ASSERTION);
                stsClient.setKeySize(256);
                token = stsClient.requestSecurityToken(STS_ENDPOINT_ADDRESS);
                LOGGER.info("Finished requesting security token.");
            }
        } catch (Exception e) {
            String msg = "Error requesting the security token from STS at: " + STS_ENDPOINT_ADDRESS
                    + ".";
//            LOGGER.debug(msg, e);
            throw new AuthenticationException(msg, e);
        }

        return token;
    }

    private Element createBasicTokenOnBehalfOf() throws ParserConfigurationException{
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.newDocument();

        // Create a Username Token
        UsernameToken oboToken = new UsernameToken(false, doc, WSConstants.PASSWORD_TEXT);
        oboToken.setName("admin");
        oboToken.setPassword("admin");
        return oboToken.getElement();
    }

}
