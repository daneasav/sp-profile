package io.despick.opensaml.init;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.Properties;

public class SAMLConfigProperties {

    public static final Logger LOGGER = LoggerFactory.getLogger(SAMLConfigProperties.class);

    public static final String SAML_CLIENT_HOME_DIR = "saml.client.home";
    public static final String SAML_RELAYSTATE = "saml.client.relaystate";
    public static final String SAML_ERROR_PAGE = "saml.client.errorpage";
    // TODO remove the old property when we cna migrate to a new one: saml.client.default.home
    private static final String SAMLCLIENT_HOME_DIR_JVM_PROPERTY = "com.sun.identity.fedlet.home";
    private static final String SAMLCLIENT_DEFAULT_RELAYSTATE_JVM_PROPERTY = "saml.client.default.relaystate";
    private static final String SAMLCLIENT_DEFAULT_ERROR_PAGE_JVM_PROPERTY = "saml.client.default.errorpage";

    private SAMLConfigProperties() {}

    private static class LazyHolder {

        private static final Properties INSTANCE = init();

        private static Properties init() {
            Properties properties = new Properties();
            properties.put(SAML_RELAYSTATE, getDefaultRelayState());
            properties.put(SAML_ERROR_PAGE, getDefaultErrorPage());
            properties.put(SAML_CLIENT_HOME_DIR, getSAMLMetadataLocation());

            return properties;
        }

        private static String getDefaultRelayState() {
            String defaultRelayState = System.getProperty(SAMLCLIENT_DEFAULT_RELAYSTATE_JVM_PROPERTY);

            if (defaultRelayState == null) {
                defaultRelayState = "/index";
            }

            return defaultRelayState;
        }

        private static String getDefaultErrorPage() {
            String defaultErrorPage = System.getProperty(SAMLCLIENT_DEFAULT_ERROR_PAGE_JVM_PROPERTY);

            if (defaultErrorPage == null) {
                defaultErrorPage = "/error";
            }

            return defaultErrorPage;
        }

        private static String getSAMLMetadataLocation() {
            String samlClientHomeDir = System.getProperty(SAMLCLIENT_HOME_DIR_JVM_PROPERTY);

            if (samlClientHomeDir == null) {
                samlClientHomeDir = System.getProperty("user.home") + File.separator + "fedlet";
            }

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

}
