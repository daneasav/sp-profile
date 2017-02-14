package io.despick.opensaml.saml;

import io.despick.opensaml.init.IDPMetadata;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPRedirectDeflateEncoder;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.metadata.Endpoint;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletResponse;

public class HTTPRedirectSender {

    public static final Logger LOGGER = LoggerFactory.getLogger(HTTPRedirectSender.class);

    public static void sendAuthnRequestRedirectMessage(HttpServletResponse response, AuthnRequest authnRequest, String binding) {
        sendRedirectMessage(response, authnRequest, IDPMetadata.getIDPSSOServiceEndpointByBinding(binding));
    }

    public static void sendLogoutRequestRedirectMessage(HttpServletResponse response, LogoutRequest logoutRequest, String binding) {
        sendRedirectMessage(response, logoutRequest, IDPMetadata.getIDPSLOServiceEndpointByBinding(binding));
    }

    public static void sendLogoutResponseRedirectMessage(HttpServletResponse response, LogoutResponse logoutResponse, String binding) {
        sendRedirectMessage(response, logoutResponse, IDPMetadata.getIDPSLOServiceEndpointByBinding(binding));
    }

    private static void sendRedirectMessage(HttpServletResponse response, SAMLObject message, Endpoint endpoint) {
        MessageContext<SAMLObject> context = new MessageContext();
        context.setMessage(message);

        SAMLPeerEntityContext peerEntityContext = context.getSubcontext(SAMLPeerEntityContext.class, true);

        SAMLEndpointContext endpointContext = peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);
        endpointContext.setEndpoint(endpoint);

        HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();

        encoder.setMessageContext(context);
        encoder.setHttpServletResponse(response);

        try {
            encoder.initialize();
        } catch (ComponentInitializationException e) {
            throw new RuntimeException(e);
        }

        LOGGER.info("Redirecting to IDP");
        try {
            encoder.encode();
        } catch (MessageEncodingException e) {
            throw new RuntimeException(e);
        }
    }

}
