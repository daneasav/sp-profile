package io.despick.opensaml.config;

import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.Properties;

public class SAMLConfigProperties {

    public static final Logger LOGGER = LoggerFactory.getLogger(SAMLConfigProperties.class);

    public static final String SAML_CLIENT_HOME = "saml.client.home";
    public static final String SAML_CLIENT_RELAY_STATE = "saml.client.relaystate";
    public static final String SAML_CLIENT_ERROR_PAGE = "saml.client.error.page";
    public static final String SAML_CLIENT_SSO_BINDING_REQUEST = "saml.client.sso.binding.request";
    public static final String SAML_CLIENT_SSO_BINDING_RESPONSE = "saml.client.sso.binding.response";
    public static final String SAML_CLIENT_SSO_AUTHN_CONTEXT = "saml.client.authn.context";
    public static final String SAML_CLIENT_SSO_AUTHN_CONTEXT_CRITERIA = "saml.client.authn.context.criteria";
    public static final String SAML_CLIENT_SLO_BINDING = "saml.client.slo.binding";
    // TODO remove this old property to SAML_CLIENT_HOME once we have this SAML client in production
    private static final String SAML_CLIENT_HOME_JVM_PROPERTY = "com.sun.identity.fedlet.home";

    private SAMLConfigProperties() {}

    private static class LazyHolder {

        private static final Properties INSTANCE = init();

        private static Properties init() {
            Properties properties = new Properties();
            properties.put(SAML_CLIENT_HOME, getSAMLMetadataLocation());
            properties.put(SAML_CLIENT_RELAY_STATE, System.getProperty(SAML_CLIENT_RELAY_STATE, "/index"));
            properties.put(SAML_CLIENT_ERROR_PAGE, System.getProperty(SAML_CLIENT_ERROR_PAGE, "/error"));
            properties.put(
                SAML_CLIENT_SSO_BINDING_REQUEST, System.getProperty(SAML_CLIENT_SSO_BINDING_REQUEST, SAMLConstants.SAML2_REDIRECT_BINDING_URI));
            properties.put(
                SAML_CLIENT_SSO_BINDING_RESPONSE, System.getProperty(SAML_CLIENT_SSO_BINDING_RESPONSE, SAMLConstants.SAML2_POST_BINDING_URI));
            properties.put(SAML_CLIENT_SSO_AUTHN_CONTEXT, System.getProperty(SAML_CLIENT_SSO_AUTHN_CONTEXT, AuthnContext.PPT_AUTHN_CTX));
            properties.put(
                SAML_CLIENT_SSO_AUTHN_CONTEXT_CRITERIA, System.getProperty(SAML_CLIENT_SSO_AUTHN_CONTEXT_CRITERIA, "exact"));
            properties.put(SAML_CLIENT_SLO_BINDING, System.getProperty(SAML_CLIENT_SLO_BINDING, SAMLConstants.SAML2_REDIRECT_BINDING_URI));

            return properties;
        }

        private static String getSAMLMetadataLocation() {
            String samlClientHomeDir = System.getProperty(SAML_CLIENT_HOME_JVM_PROPERTY,
                System.getProperty("user.home") + File.separator + "fedlet");

            if (samlClientHomeDir == null && samlClientHomeDir.endsWith("/")) {
                samlClientHomeDir = samlClientHomeDir.substring(0, samlClientHomeDir.length() - 1);
            }

            verifyConfigDirectory(samlClientHomeDir);

            LOGGER.info("Fallback to the default fedlet configuration directory in user home: '{}'.",
                new File(samlClientHomeDir).getAbsolutePath());

            return samlClientHomeDir;
        }

        private static void verifyConfigDirectory(String samlClientConfigDir) {
            File samlClientDirectory = new File(samlClientConfigDir);
            if (!samlClientDirectory.exists() || !samlClientDirectory.isDirectory() ||
                samlClientDirectory.listFiles() == null || samlClientDirectory.listFiles().length == 0) {
                throw new IllegalStateException("Missing, inaccessible or empty configuration directory, please make " +
                    "sure the following directory exists, can be opened and contains configuration files: " +
                    samlClientDirectory.getAbsolutePath());
            }

            LOGGER.info("Verified that the config directory exists, is accessible and is not empty.");
        }

    }

    public static Properties getInstance() {
        return LazyHolder.INSTANCE;
    }

    public static String getHome() {
        return getInstance().getProperty(SAML_CLIENT_HOME);
    }

    public static String getRelayState() {
        return getInstance().getProperty(SAML_CLIENT_RELAY_STATE);
    }

    public static String getErrorPage() {
        return getInstance().getProperty(SAML_CLIENT_ERROR_PAGE);
    }

    public static String getSSOBindingRequest() {
        return getInstance().getProperty(SAML_CLIENT_SSO_BINDING_REQUEST);
    }

    public static String getSSOBindingResponse() {
        return getInstance().getProperty(SAML_CLIENT_SSO_BINDING_RESPONSE);
    }

    public static String getSSOAuthnContext() {
        return getInstance().getProperty(SAML_CLIENT_SSO_AUTHN_CONTEXT);
    }

    /*public static String getAuthnContextCriteria() {
        return getInstance().getProperty(SAML_CLIENT_SSO_AUTHN_CONTEXT_CRITERIA);
    }*/

    public static String getSLOBinding() {
        return getInstance().getProperty(SAML_CLIENT_SLO_BINDING);
    }

}
