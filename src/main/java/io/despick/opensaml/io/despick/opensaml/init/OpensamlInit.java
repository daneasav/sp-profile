package io.despick.opensaml.io.despick.opensaml.init;

import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.saml.common.xml.SAMLSchemaBuilder;
import org.opensaml.saml.metadata.resolver.impl.FilesystemMetadataResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;

/**
 * Created by DaneasaV on 21.11.2016.
 */

@WebListener
public class OpensamlInit implements ServletContextListener {
  public static final Logger LOGGER = LoggerFactory.getLogger(OpensamlInit.class);

  @Override public void contextInitialized(ServletContextEvent servletContextEvent) {
    try {
      InitializationService.initialize();

      //XMLObjectProviderRegistrySupport.getMarshallerFactory()
      //XMLObjectProviderRegistrySupport.getBuilderFactory()
      //XMLObjectProviderRegistrySupport.getUnmarshallerFactory()
      //Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(qName);
      //DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
      //documentBuilderFactory.setNamespaceAware(true);
      //DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
      //UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();

      //org.opensaml.core.xml.config.XMLObjectProviderInitializer
      //org.opensaml.core.xml.config.GlobalParserPoolInitializer
      //org.opensaml.saml.config.XMLObjectProviderInitializer
      //org.opensaml.saml.config.SAMLConfigurationInitializer
      //org.opensaml.xmlsec.config.XMLObjectProviderInitializer

      //BasicCredential

      try {
        FilesystemMetadataResolver idpMetadataResolver = new FilesystemMetadataResolver(new File("idp.xml"));
        FilesystemMetadataResolver spMetadataResolver = new FilesystemMetadataResolver(new File("sp.xml"));
        sp.

      } catch (ResolverException e) {
        LOGGER.error("Metadata failed", e);
      }
    } catch (InitializationException e) {
      LOGGER.error("Initialization failed", e);
    }

    //SAMLSchemaBuilder
  }

  @Override public void contextDestroyed(ServletContextEvent servletContextEvent) {

  }
}
