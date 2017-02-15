package io.despick.opensaml.saml;

import io.despick.opensaml.config.SPMetadata;
import net.shibboleth.utilities.java.support.security.RandomIdentifierGenerationStrategy;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.Issuer;

import javax.xml.namespace.QName;

public class SAMLUtil {

    private static final RandomIdentifierGenerationStrategy secureRandomIdGenerator = new RandomIdentifierGenerationStrategy();

    public static String getRandomID() {
        return secureRandomIdGenerator.generateIdentifier();
    }

    public static <T> T buildSAMLObject(final Class<T> clazz) {
        T object;
        try {
            XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
            QName defaultElementName = (QName)clazz.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
            object = (T) builderFactory.getBuilder(defaultElementName).buildObject(defaultElementName);
        } catch (IllegalAccessException e) {
            throw new IllegalArgumentException("Could not create SAML object");
        } catch (NoSuchFieldException e) {
            throw new IllegalArgumentException("Could not create SAML object");
        }

        return object;
    }

    public static Issuer buildSPIssuer() {
        Issuer issuer = SAMLUtil.buildSAMLObject(Issuer.class);
        issuer.setValue(SPMetadata.getInstance().getEntityID());

        return issuer;
    }

}
