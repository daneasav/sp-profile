package io.despick.opensaml.config;

import io.despick.opensaml.error.SAMLClientException;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.metadata.resolver.impl.FilesystemMetadataResolver;
import org.opensaml.saml.saml2.metadata.*;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.signature.X509Certificate;
import org.opensaml.xmlsec.signature.X509Data;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.bind.DatatypeConverter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.List;

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

    public static List<Credential> getIDPSigningCertificates() {
        List<Credential> certificates = new ArrayList<>();

        for (KeyDescriptor keyDescriptor : getIDPSSODescriptor().getKeyDescriptors()) {
            if (keyDescriptor.getUse().equals(UsageType.SIGNING)) {
                // we only support x509 certificates
                for (X509Data x509Data : keyDescriptor.getKeyInfo().getX509Datas()) {
                    for (X509Certificate x509Certificate : x509Data.getX509Certificates()) {
                        try {
                            certificates.add(getCertificate(x509Certificate.getValue()));
                        } catch (CertificateException e) {
                            LOGGER.error("Certificate is invalid " + x509Certificate.getValue());
                        }
                    }
                }
            }
        }

        return certificates;
    }

    private static BasicCredential getCertificate(String b64data) throws CertificateException {
        byte[] decodedCertificate = DatatypeConverter.parseBase64Binary(b64data);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Certificate certificate = certificateFactory.generateCertificate(new ByteArrayInputStream(decodedCertificate));

        BasicCredential credential = new BasicCredential(certificate.getPublicKey());
        credential.setEntityId(getInstance().getEntityID());

        return credential;
    }

}
