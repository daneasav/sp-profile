package io.despick.opensaml.web;

import io.despick.opensaml.saml.*;
import io.despick.opensaml.session.UserSession;
import io.despick.opensaml.session.UserSessionManager;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebServlet(name = "sloServlet", urlPatterns = "/sloRedirect")
public class SingleLogoutServlet extends AbstractSAMLClientServlet {

    private static Logger LOGGER = LoggerFactory.getLogger(SingleLogoutServlet.class);

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        LogoutRequest logoutRequest = HTTPRedirectDecoder.buildLogoutRequestFromRequest(request);

        handleSLORequest(request, logoutRequest);

        HTTPRedirectSender.sendLogoutResponseRedirectMessage(response, SingleLogout.buildLogoutResponse(logoutRequest.getID()));
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        LogoutRequest logoutRequest = HTTPPostDecoder.buildLogoutRequestFromRequest(request);

        handleSLORequest(request, logoutRequest);

        HTTPPostSender.sendLogoutResponsePostMessage(response, SingleLogout.buildLogoutResponse(logoutRequest.getID()));
    }

    private void handleSLORequest(HttpServletRequest request, LogoutRequest logoutRequest) {
        if (UserSessionManager.isUserSession(request)) {
            UserSession userSession = UserSessionManager.getUserSession(request);

            if (userSession.getSamlNameID().getValue().equals(logoutRequest.getNameID().getValue())
                && userSession.getSamlSessionIndex().equals(logoutRequest.getSessionIndexes().get(0).getSessionIndex())) {
                LOGGER.info("Invalidate current session");
            } else {
                LOGGER.error("The nameID and/or the session index do not match, logging out nonetheless");
            }
        } else {
            LOGGER.error("There is no session, logging out nonetheless.");
        }

        UserSessionManager.removeUserSession(request);
    }

}
