package io.despick.opensaml.web;

import io.despick.opensaml.saml.HTTPRedirectDecoder;
import io.despick.opensaml.saml.HTTPRedirectSender;
import io.despick.opensaml.saml.SingleLogout;
import io.despick.opensaml.saml.session.UserSession;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebServlet(name = "sloResponseServlet", urlPatterns = "/sloRedirect") public class SingleLogoutResponseServlet
    extends HttpServlet {

    private static Logger LOGGER = LoggerFactory.getLogger(SingleLogoutResponseServlet.class);

    @Override protected void doGet(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
        LogoutRequest logoutRequest = HTTPRedirectDecoder.buildLogoutRequestFromRequest(request);

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

        HTTPRedirectSender.sendLogoutResponseRedirectMessage(response,
            new SingleLogout().buildLogoutResponse(logoutRequest.getID()), SAMLConstants.SAML2_REDIRECT_BINDING_URI);
    }

}
