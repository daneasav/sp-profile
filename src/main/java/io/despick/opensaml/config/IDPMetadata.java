package io.despick.opensaml.config;

import io.despick.opensaml.error.SAMLClientException;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.metadata.resolver.impl.FilesystemMetadataResolver;
import org.opensaml.saml.saml2.metadata.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;

public class IDPMetadata {

    public static final Logger LOGGER = LoggerFactory.getLogger(IDPMetadata.class);

    private IDPMetadata() {}

    private static class LazyHolder {
        private static final EntityDescriptor INSTANCE = init();

        private static EntityDescriptor init() {
            try {
                // get the IDP SAML metadata
                String path = SAMLConfigProperties.getHome() + File.separator + "idp.xml";
                FilesystemMetadataResolver idpMetadataResolver = new FilesystemMetadataResolver(new File(path));
                idpMetadataResolver.setId("idp");
                idpMetadataResolver.setParserPool(InitializedParserPool.getInstance());
                idpMetadataResolver.initialize();

                return idpMetadataResolver.iterator().next();
            } catch (ResolverException | ComponentInitializationException e) {
                LOGGER.error("IDP Metadata is invalid", e);
                throw new SAMLClientException("IDP Metadata is invalid");
            }
        }
    }

    public static EntityDescriptor getInstance() {
        return LazyHolder.INSTANCE;
    }

    public static IDPSSODescriptor getIDPSSODescriptor() {
        return getInstance().getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
    }

    public static String getArtifactResolutionService() {
        ArtifactResolutionService artifactResolutionService = getIDPSSODescriptor().getDefaultArtifactResolutionService();

        if (artifactResolutionService == null) {
            if (getIDPSSODescriptor().getArtifactResolutionServices().size() > 0) {
                artifactResolutionService = getIDPSSODescriptor().getArtifactResolutionServices().get(0);
            } else {
                LOGGER.error("No artifact resolution service found");
                throw new SAMLClientException("No artifact resolution service found");
            }
        }

        return artifactResolutionService.getLocation();
    }

    public static Endpoint getIDPSSOServiceEndpointByBinding(String binding) {
        for (SingleSignOnService ssoService : getIDPSSODescriptor().getSingleSignOnServices()) {
            if (ssoService.getBinding().equals(binding)) {
                return ssoService;
            }
        }

        LOGGER.error("IDP SSO Service was not found for {0} binding", binding);
        throw new SAMLClientException("IDP SSO Service was not found for " + binding + " binding");
    }

    public static Endpoint getIDPSLOServiceEndpointByBinding(String binding) {
        for (SingleLogoutService singleLogoutService : getIDPSSODescriptor().getSingleLogoutServices()) {
            if (singleLogoutService.getBinding().equals(binding)) {
                return singleLogoutService;
            }
        }

        LOGGER.error("IDP SLO Service was not found for {0} binding", binding);
        throw new SAMLClientException("IDP SLO Service was not found for " + binding + " binding");
    }

}
