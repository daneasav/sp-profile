package io.despick.opensaml.error;

public class SAMLClientException extends RuntimeException {

    public SAMLClientException() {
    }

    public SAMLClientException(String message) {
        super(message);
    }

    public SAMLClientException(String message, Throwable cause) {
        super(message, cause);
    }
}
