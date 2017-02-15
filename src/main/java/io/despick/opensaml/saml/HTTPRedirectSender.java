package io.despick.opensaml.saml;

import io.despick.opensaml.config.IDPMetadata;
import io.despick.opensaml.config.SAMLConfigProperties;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.messaging.context.SAMLBindingContext;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.xml.SAMLConstants;
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

    public static void sendAuthnRequestRedirectMessage(HttpServletResponse response, AuthnRequest authnRequest) {
        sendRedirectMessage(response, authnRequest, IDPMetadata.getIDPSSOServiceEndpointByBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI),
            SAMLConfigProperties.getRelayState());
    }

    public static void sendLogoutRequestRedirectMessage(HttpServletResponse response, LogoutRequest logoutRequest) {
        sendRedirectMessage(response, logoutRequest, IDPMetadata.getIDPSLOServiceEndpointByBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI),
            SAMLConfigProperties.getRelayState());
    }

    public static void sendLogoutResponseRedirectMessage(HttpServletResponse response, LogoutResponse logoutResponse) {
        sendRedirectMessage(response, logoutResponse, IDPMetadata.getIDPSLOServiceEndpointByBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI),
            SAMLConfigProperties.getRelayState());
    }

    public static void sendAuthnRequestRedirectMessage(HttpServletResponse response, AuthnRequest authnRequest, String relayState) {
        sendRedirectMessage(response, authnRequest, IDPMetadata.getIDPSSOServiceEndpointByBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI), relayState);
    }

    public static void sendLogoutRequestRedirectMessage(HttpServletResponse response, LogoutRequest logoutRequest, String relayState) {
        sendRedirectMessage(response, logoutRequest, IDPMetadata.getIDPSLOServiceEndpointByBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI), relayState);
    }

    public static void sendLogoutResponseRedirectMessage(HttpServletResponse response, LogoutResponse logoutResponse, String relayState) {
        sendRedirectMessage(response, logoutResponse, IDPMetadata.getIDPSLOServiceEndpointByBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI), relayState);
    }

    private static void sendRedirectMessage(HttpServletResponse response, SAMLObject message, Endpoint endpoint, String relayState) {
        MessageContext<SAMLObject> context = new MessageContext();
        context.setMessage(message);

        SAMLPeerEntityContext peerEntityContext = context.getSubcontext(SAMLPeerEntityContext.class, true);

        SAMLEndpointContext endpointContext = peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);
        endpointContext.setEndpoint(endpoint);

        SAMLBindingContext bindingContext = context.getSubcontext(SAMLBindingContext.class, true);
        bindingContext.setRelayState(relayState);

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
