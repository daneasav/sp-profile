package io.despick.opensaml.example;

import io.despick.opensaml.init.SamlMetadata;
import io.despick.opensaml.saml.SingleLogout;
import io.despick.opensaml.saml.UserSession;
import io.despick.opensaml.web.AuthFilter;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPRedirectDeflateEncoder;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Created by DaneasaV on 13.02.2017.
 */

@WebServlet(name = "logoutServlet", urlPatterns = "/logout")
public class LogoutButton extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        if (request.getSession().getAttribute(AuthFilter.AUTHENTICATED_SESSION_ATTRIBUTE) != null) {
            UserSession userSession = (UserSession) request.getSession().getAttribute(AuthFilter.AUTHENTICATED_SESSION_ATTRIBUTE);
            LogoutRequest logoutRequest = new SingleLogout().buildLogoutRequest(userSession);

            MessageContext context = new MessageContext();
            context.setMessage(logoutRequest);

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

            //LOGGER.info("Redirecting to IDP");
            try {
                encoder.encode();
            } catch (MessageEncodingException e) {
                throw new RuntimeException(e);
            }
        } else {
            //do nothing. user is not logged in
        }
    }

    private Endpoint getIDPEndpointByBinding(IDPSSODescriptor idpssoDescriptor, String binding) {
        for (SingleLogoutService sloService : idpssoDescriptor.getSingleLogoutServices()) {
            if (sloService.getBinding().equals(binding)) {
                return sloService;
            }
        }

        return null;
    }

}
