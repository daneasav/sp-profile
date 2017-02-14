package io.despick.opensaml.error;

/**
 * Created by DaneasaV on 14.02.2017.
 */
public class SAMLClientException extends RuntimeException {

    public SAMLClientException() {
    }

    public SAMLClientException(String message) {
        super(message);
    }
}
