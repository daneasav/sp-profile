package io.despick.opensaml.init;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.saml.metadata.resolver.impl.FilesystemMetadataResolver;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.xmlsec.config.JavaCryptoValidationInitializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;
import java.io.File;

@WebListener()
public class OpenSAMLInit implements ServletContextListener {

    public static final Logger LOGGER = LoggerFactory.getLogger(OpenSAMLInit.class);

    @Override public void contextInitialized(ServletContextEvent servletContextEvent) {
        try {
            // verify that jce is correctly initialized
            JavaCryptoValidationInitializer javaCryptoValidationInitializer = new JavaCryptoValidationInitializer();
            javaCryptoValidationInitializer.init();

            //initialize the opensaml library
            InitializationService.initialize();

            //initialize an xml parser pool
            BasicParserPool parserPool = new BasicParserPool();
            parserPool.initialize();

            try {
                // get the IDP SAML metadata
                FilesystemMetadataResolver idpMetadataResolver = new FilesystemMetadataResolver(new File("idp.xml"));
                idpMetadataResolver.setId("idp");
                idpMetadataResolver.setParserPool(parserPool);
                idpMetadataResolver.initialize();
                SamlMetadata.idpDescriptor = idpMetadataResolver.iterator().next();

                IDPSSODescriptor idpssoDescriptor = SamlMetadata.idpDescriptor.getIDPSSODescriptor("urn:oasis:names:tc:SAML:2.0:protocol");

                // get the SP SAML metadata
                FilesystemMetadataResolver spMetadataResolver = new FilesystemMetadataResolver(new File("sp.xml"));
                spMetadataResolver.setId("idp");
                spMetadataResolver.setParserPool(parserPool);
                spMetadataResolver.initialize();
                SamlMetadata.spDescriptor = spMetadataResolver.iterator().next();
            } catch (ResolverException e) {
                LOGGER.error("Metadata is invalid", e);
            }
        } catch (InitializationException e) {
            LOGGER.error("Initialization failed", e);
            throw new RuntimeException(e.getMessage(), e);
        } catch (ComponentInitializationException e) {
            LOGGER.error("Metadata init failed", e);
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @Override public void contextDestroyed(ServletContextEvent servletContextEvent) {

    }
}
