package io.despick.opensaml.saml;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;

public class HTTPPostDecoder {

    private static Logger LOGGER = LoggerFactory.getLogger(HTTPPostDecoder.class);

    public static Response buildResponseFromRequest(HttpServletRequest request) {
        MessageContext<SAMLObject> messageContext = buildSAMLObjectFromRequest(request);

        if (Response.DEFAULT_ELEMENT_LOCAL_NAME.equals(messageContext.getMessage().getElementQName().getLocalPart())) {
            return (Response) messageContext.getMessage();
        }

        LOGGER.error("Could not decode the Response message" + messageContext.getMessage());
        return null;
    }

    public static LogoutRequest buildLogoutRequestFromRequest(HttpServletRequest request) {
        MessageContext<SAMLObject> messageContext = buildSAMLObjectFromRequest(request);

        if (LogoutRequest.DEFAULT_ELEMENT_LOCAL_NAME.equals(messageContext.getMessage().getElementQName().getLocalPart())) {
            return (LogoutRequest) messageContext.getMessage();
        }

        LOGGER.error("Could not decode the Logout Request message" + messageContext.getMessage());
        return null;
    }

    public static LogoutResponse buildLogoutResponseFromRequest(HttpServletRequest request) {
        MessageContext<SAMLObject> messageContext = buildSAMLObjectFromRequest(request);

        if (LogoutResponse.DEFAULT_ELEMENT_LOCAL_NAME.equals(messageContext.getMessage().getElementQName().getLocalPart())) {
            return (LogoutResponse) messageContext.getMessage();
        }

        LOGGER.error("Could not decode the Logout Response message" + messageContext.getMessage());
        return null;
    }

    private static MessageContext<SAMLObject> buildSAMLObjectFromRequest(HttpServletRequest request) {
        org.opensaml.saml.saml2.binding.decoding.impl.HTTPPostDecoder decoder
            = new org.opensaml.saml.saml2.binding.decoding.impl.HTTPPostDecoder();
        decoder.setHttpServletRequest(request);
        try {
            decoder.initialize();
        } catch (ComponentInitializationException e) {
            LOGGER.error("Exception initializing the decoder for saml response ", e);
        }

        try {
            decoder.decode();
        } catch (MessageDecodingException e) {
            LOGGER.error("Exception while decoding saml response ", e);
        }

        return decoder.getMessageContext();
    }

}
