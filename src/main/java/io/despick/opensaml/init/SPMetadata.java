package io.despick.opensaml.init;

import io.despick.opensaml.error.SAMLClientException;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.metadata.resolver.impl.FilesystemMetadataResolver;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;

public class SPMetadata {

    public static final Logger LOGGER = LoggerFactory.getLogger(SPMetadata.class);

    private SPMetadata() {}

    private static class LazyHolder {
        private static final EntityDescriptor INSTANCE = init();

        private static EntityDescriptor init() {
            try {
                // get the SP SAML metadata
                String path = SAMLConfigProperties.getInstance().getProperty(SAMLConfigProperties.SAML_CLIENT_HOME_DIR)
                    + File.separator + "sp.xml";
                FilesystemMetadataResolver spMetadataResolver = new FilesystemMetadataResolver(new File(path));
                spMetadataResolver.setId("sp");
                spMetadataResolver.setParserPool(InitializedParserPool.getInstance());
                spMetadataResolver.initialize();

                return spMetadataResolver.iterator().next();
            } catch (ResolverException | ComponentInitializationException e) {
                LOGGER.error("SP Metadata is invalid", e);
                throw new SAMLClientException("SP Metadata is invalid");
            }
        }
    }

    public static EntityDescriptor getInstance() {
        return LazyHolder.INSTANCE;
    }

    public static SPSSODescriptor getSPSSODescriptor() {
        return getInstance().getSPSSODescriptor(SAMLConstants.SAML20P_NS);
    }

    public static String getAssertionConsumerEndpoint(String binding) {
        for (AssertionConsumerService assertionConsumerService : getSPSSODescriptor().getAssertionConsumerServices()) {
            if (assertionConsumerService.getBinding().equals(binding)) {
                return assertionConsumerService.getLocation();
            }
        }

        LOGGER.error("SP Assertion Consumer Service was not found for {0} binding", binding);
        throw new SAMLClientException("SP Assertion Consumer Service was not found for " + binding + " binding");
    }

}
