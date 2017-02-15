package io.despick.opensaml.web;

import io.despick.opensaml.error.SAMLClientException;
import io.despick.opensaml.saml.HTTPPostDecoder;
import io.despick.opensaml.session.UserSessionManager;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebServlet(name = "postACSServlet", urlPatterns = "/acsPost")
public class PostAssertionConsumerServlet extends HttpServlet {

    private static Logger LOGGER = LoggerFactory.getLogger(PostAssertionConsumerServlet.class);

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) {
        Response samlResponse = HTTPPostDecoder.buildResponseFromRequest(request);

        if (StatusCode.SUCCESS.equals(samlResponse.getStatus().getStatusCode().getValue())) {
            if (samlResponse.getAssertions().size() == 1) {
                Assertion assertion = samlResponse.getAssertions().get(0);
                UserSessionManager.setUserSession(request, UserSessionManager.getUserSession(assertion));
            }
        } else {
            // TODO redirect to default error page
        }

        try {
            // TODO send redirect to default page or to RelayState
            response.sendRedirect("/opensaml/index");
        } catch (IOException e) {
            LOGGER.error("Error while redirecting to: ");
            throw new SAMLClientException(e.getMessage());
        }
    }

}
