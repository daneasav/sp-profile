package io.despick.opensaml.init;

import net.shibboleth.utilities.java.support.security.RandomIdentifierGenerationStrategy;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;

public class SamlMetadata {

    public static EntityDescriptor spDescriptor;
    public static EntityDescriptor idpDescriptor;

    public static RandomIdentifierGenerationStrategy secureRandomIdGenerator = new RandomIdentifierGenerationStrategy();

}
