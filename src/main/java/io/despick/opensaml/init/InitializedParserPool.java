package io.despick.opensaml.init;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class InitializedParserPool extends BasicParserPool {

    public static final Logger LOGGER = LoggerFactory.getLogger(InitializedParserPool.class);

    private InitializedParserPool() {
        try {
            initialize();
        } catch (ComponentInitializationException e) {
            LOGGER.error("XML Parser pool was not initialized correctly", e);
        }
    }

    private static class LazyHolder {
        private static final InitializedParserPool INSTANCE = new InitializedParserPool();
    }

    public static BasicParserPool getInstance() {
        return LazyHolder.INSTANCE;
    }

}
