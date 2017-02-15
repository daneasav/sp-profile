package io.despick.opensaml.config;

import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.xmlsec.config.JavaCryptoValidationInitializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;

@WebListener()
public class OpenSAMLInit implements ServletContextListener {

    public static final Logger LOGGER = LoggerFactory.getLogger(OpenSAMLInit.class);

    @Override
    public void contextInitialized(ServletContextEvent servletContextEvent) {
        try {
            // verify that jce is correctly initialized
            JavaCryptoValidationInitializer javaCryptoValidationInitializer = new JavaCryptoValidationInitializer();
            javaCryptoValidationInitializer.init();

            //getInstance the opensaml library
            InitializationService.initialize();

            // read SAML config files
            LOGGER.info("IDP metadata is: {0}", IDPMetadata.getInstance().toString());
            LOGGER.info("SP metadata is: {0}", SPMetadata.getInstance().toString());


        } catch (InitializationException e) {
            LOGGER.error("Initialization failed", e);
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @Override
    public void contextDestroyed(ServletContextEvent servletContextEvent) {

    }
}
