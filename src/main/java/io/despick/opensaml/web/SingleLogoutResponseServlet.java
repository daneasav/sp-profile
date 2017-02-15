package io.despick.opensaml.web;

import io.despick.opensaml.saml.HTTPRedirectDecoder;
import io.despick.opensaml.session.UserSessionManager;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.StatusCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebServlet(name = "sloResponseServlet", urlPatterns = "/sloRedirectResponse")
public class SingleLogoutResponseServlet extends AbstractSAMLClientServlet {

    private static Logger LOGGER = LoggerFactory.getLogger(SingleLogoutResponseServlet.class);

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        LogoutResponse logoutResponse = HTTPRedirectDecoder.buildLogoutResponseFromRequest(request);

        if (StatusCode.SUCCESS.equals(logoutResponse.getStatus().getStatusCode().getValue())) {
            LOGGER.info("Invalidate current session");
            UserSessionManager.removeUserSession(request);

            redirectToRelayState(request, response);
        } else {
            LOGGER.error("logout response was not success.");

            redirectToErrorPage(response);
        }
    }

}
