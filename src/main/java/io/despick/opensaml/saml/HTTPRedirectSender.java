package io.despick.opensaml.saml;

import io.despick.opensaml.error.SAMLClientException;
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
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletResponse;

/**
 * Created by DaneasaV on 13.02.2017.
 */
public class HTTPRedirectSender {

    public static final Logger LOGGER = LoggerFactory.getLogger(HTTPRedirectSender.class);

    public static void sendAuthnRequestRedirectMessage(HttpServletResponse response, AuthnRequest authnRequest,
        IDPSSODescriptor idpssoDescriptor, String binding) {
        sendRedirectMessage(response, authnRequest, getIDPSSOServiceEndpointByBinding(idpssoDescriptor, binding));
    }

    public static void sendLogoutRequestRedirectMessage(HttpServletResponse response, LogoutRequest logoutRequest,
        IDPSSODescriptor idpssoDescriptor, String binding) {
        sendRedirectMessage(response, logoutRequest, getIDPSLOServiceEndpointByBinding(idpssoDescriptor, binding));
    }

    public static void sendLogoutResponseRedirectMessage(HttpServletResponse response, LogoutResponse logoutResponse,
        IDPSSODescriptor idpssoDescriptor, String binding) {
        sendRedirectMessage(response, logoutResponse, getIDPSLOServiceEndpointByBinding(idpssoDescriptor, binding));
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

    private static Endpoint getIDPSSOServiceEndpointByBinding(IDPSSODescriptor idpssoDescriptor, String binding) {
        for (SingleSignOnService ssoService : idpssoDescriptor.getSingleSignOnServices()) {
            if (ssoService.getBinding().equals(binding)) {
                return ssoService;
            }
        }

        LOGGER.error("IDP SSO Service was not found for {0} binding", binding);
        throw new SAMLClientException("IDP SSO Service was not found for " + binding + " binding");
    }

    private static Endpoint getIDPSLOServiceEndpointByBinding(IDPSSODescriptor idpssoDescriptor, String binding) {
        for (SingleLogoutService singleLogoutService : idpssoDescriptor.getSingleLogoutServices()) {
            if (singleLogoutService.getBinding().equals(binding)) {
                return singleLogoutService;
            }
        }

        LOGGER.error("IDP SLO Service was not found for {0} binding", binding);
        throw new SAMLClientException("IDP SLO Service was not found for " + binding + " binding");
    }

}
