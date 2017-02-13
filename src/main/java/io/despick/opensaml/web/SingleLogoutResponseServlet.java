package io.despick.opensaml.web;

import io.despick.opensaml.init.SamlMetadata;
import io.despick.opensaml.saml.SingleLogout;
import io.despick.opensaml.saml.UserSession;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPRedirectDeflateDecoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPRedirectDeflateEncoder;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Created by DaneasaV on 13.02.2017.
 */

@WebServlet(name = "sloResponseServlet", urlPatterns = "/sloRedirect") public class SingleLogoutResponseServlet
    extends HttpServlet {

    private static Logger LOGGER = LoggerFactory.getLogger(SingleLogoutResponseServlet.class);

    @Override protected void doGet(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
        LogoutRequest logoutRequest = buildLogoutRequestFromRequest(request);

        if (request.getSession().getAttribute(AuthFilter.AUTHENTICATED_SESSION_ATTRIBUTE) != null) {
            UserSession userSession = (UserSession) request.getSession().getAttribute(AuthFilter.AUTHENTICATED_SESSION_ATTRIBUTE);

            if (userSession.getSamlNameID().getValue().equals(logoutRequest.getNameID().getValue())
                && userSession.getSamlSessionIndex().equals(logoutRequest.getSessionIndexes().get(0).getSessionIndex())) {
                LOGGER.info("invalidate session " + request.getSession().getId());
            } else {
                LOGGER.error("The nameID and/or the session index do not match, logging out nonetheless");
            }
        } else {
            LOGGER.error("There is no session, logging out nonetheless.");
        }

        request.getSession().invalidate();

        MessageContext context = new MessageContext();
        context.setMessage(new SingleLogout().buildLogoutResponse(logoutRequest.getID()));

        SAMLPeerEntityContext peerEntityContext = context.getSubcontext(SAMLPeerEntityContext.class, true);

        SAMLEndpointContext endpointContext = peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);
        endpointContext.setEndpoint(getIDPEndpointByBinding(
            SamlMetadata.idpDescriptor.getIDPSSODescriptor(SAMLConstants.SAML20P_NS),
            SAMLConstants.SAML2_REDIRECT_BINDING_URI));

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

    private LogoutRequest buildLogoutRequestFromRequest(HttpServletRequest request) {
        HTTPRedirectDeflateDecoder decoder = new HTTPRedirectDeflateDecoder();
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

        MessageContext<SAMLObject> messageContext = decoder.getMessageContext();
        if (LogoutRequest.DEFAULT_ELEMENT_LOCAL_NAME.equals(messageContext.getMessage().getElementQName().getLocalPart())) {
            return (LogoutRequest) messageContext.getMessage();
        }

        return null;
    }

    private Endpoint getIDPEndpointByBinding(IDPSSODescriptor idpssoDescriptor, String binding) {
        for (SingleLogoutService singleLogoutService : idpssoDescriptor.getSingleLogoutServices()) {
            if (singleLogoutService.getBinding().equals(binding)) {
                return singleLogoutService;
            }
        }

        // TODO: return fallback binding
        return null;
    }

}
