package io.despick.opensaml.web;

import io.despick.opensaml.error.SAMLClientException;
import io.despick.opensaml.init.SAMLConfigProperties;
import io.despick.opensaml.session.UserSessionManager;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AbstractSAMLClientServlet extends HttpServlet {

    private static Logger LOGGER = LoggerFactory.getLogger(AbstractSAMLClientServlet.class);

    public static final String RELAYSTATE_QUERY_PARAMETER = "RelayState";

    protected void redirectToRelayState(HttpServletRequest request, HttpServletResponse response) {
        String redirectPage = request.getParameter(RELAYSTATE_QUERY_PARAMETER);
        if (redirectPage == null) {
            redirectPage = SAMLConfigProperties.getRelayState();
        }

        try {
            response.sendRedirect(redirectPage);
        } catch (IOException e) {
            LOGGER.error("Error while redirecting to: " + redirectPage);
            throw new SAMLClientException(e.getMessage());
        }
    }

    protected void redirectToErrorPage(HttpServletResponse response) {
        try {
            LOGGER.error("Redirecting to:" + SAMLConfigProperties.getErrorPage());
            response.sendRedirect(SAMLConfigProperties.getErrorPage());
        } catch (IOException e) {
            LOGGER.error("Error while redirecting to: " + SAMLConfigProperties.getErrorPage());
            throw new SAMLClientException(e.getMessage());
        }
    }

    protected void handleAuthnResponse(HttpServletRequest request, HttpServletResponse response, Response samlResponse) {
        if (StatusCode.SUCCESS.equals(samlResponse.getStatus().getStatusCode().getValue())) {
            if (samlResponse.getAssertions().size() == 1) {
                Assertion assertion = samlResponse.getAssertions().get(0);
                UserSessionManager.setUserSession(request, UserSessionManager.getUserSession(assertion));

                redirectToRelayState(request, response);
            } else {
                // TODO handle the error
            }
        } else {
            // TODO check for passive auth requests before sending to an error page
            LOGGER.error("The authentication response was not successful: " + samlResponse.getStatus().getStatusCode().getValue());

            redirectToErrorPage(response);
        }
    }
}
