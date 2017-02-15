package io.despick.opensaml.error;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SAMLClientException extends RuntimeException {

    private static Logger LOGGER = LoggerFactory.getLogger(SAMLClientException.class);

    public SAMLClientException() {
        LOGGER.error("An exception was triggered", this);
    }

    public SAMLClientException(String message) {
        super(message);
        LOGGER.error("An exception was triggered with the message: " + message, this);
    }

    public SAMLClientException(String message, Throwable cause) {
        super(message, cause);
        LOGGER.error("An exception was triggered with the message: " + message, cause);
    }
}
