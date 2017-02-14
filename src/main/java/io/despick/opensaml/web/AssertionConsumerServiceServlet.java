package io.despick.opensaml.web;

import io.despick.opensaml.saml.HTTPArtifactSender;
import io.despick.opensaml.saml.SingleSignOn;
import io.despick.opensaml.saml.session.UserSessionManager;
import org.opensaml.saml.saml2.core.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebServlet(name = "acsServlet", urlPatterns = "/acsArtifact")
public class AssertionConsumerServiceServlet extends HttpServlet {

    private static Logger LOGGER = LoggerFactory.getLogger(AssertionConsumerServiceServlet.class);

    public static final String SAMLART_QUERY_PARAMETER = "SAMLart";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
        LOGGER.info("Artifact received");
        Artifact artifact = SingleSignOn.buildArtifact(request.getParameter(SAMLART_QUERY_PARAMETER));
        LOGGER.info("Artifact: " + artifact.getArtifact());

        ArtifactResolve artifactResolve = SingleSignOn.buildArtifactResolve(artifact);
        LOGGER.info("Sending ArtifactResolve");

        ArtifactResponse artifactResponse = HTTPArtifactSender.resolveAndReceiveArtifactResponse(request, artifactResolve);

        if (Response.DEFAULT_ELEMENT_LOCAL_NAME.equals(artifactResponse.getMessage().getElementQName().getLocalPart())) {
            if (artifactResponse.getMessage().hasChildren()) {
                // get the first one since the IDP only sends one assertion
                Response samlResponse = (Response) artifactResponse.getMessage();

                //TODO check the number of assertions
                if (samlResponse.getAssertions().size() == 1) {
                    Assertion assertion = samlResponse.getAssertions().get(0);
                    UserSessionManager.setUserSession(request, UserSessionManager.getUserSession(assertion));
                }

            }
        }

        try {
            response.sendRedirect("/opensaml/index");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
