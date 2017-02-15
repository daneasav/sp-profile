package io.despick.opensaml.web;

import io.despick.opensaml.saml.HTTPArtifactSenderReceiver;
import io.despick.opensaml.saml.SingleSignOn;
import org.opensaml.saml.saml2.core.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebServlet(name = "artifactACSServlet", urlPatterns = "/acsArtifact")
public class ArtifactAssertionConsumerServiceServlet extends AbstractSAMLClientServlet {

    private static Logger LOGGER = LoggerFactory.getLogger(ArtifactAssertionConsumerServiceServlet.class);

    public static final String SAMLART_QUERY_PARAMETER = "SAMLart";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
        LOGGER.info("Artifact received");
        Artifact artifact = SingleSignOn.buildArtifact(request.getParameter(SAMLART_QUERY_PARAMETER));
        LOGGER.info("Artifact: " + artifact.getArtifact());

        ArtifactResolve artifactResolve = SingleSignOn.buildArtifactResolve(artifact);
        LOGGER.info("Sending ArtifactResolve");

        ArtifactResponse artifactResponse = HTTPArtifactSenderReceiver
            .resolveAndReceiveArtifactResponse(request, artifactResolve);

        if (Response.DEFAULT_ELEMENT_LOCAL_NAME.equals(artifactResponse.getMessage().getElementQName().getLocalPart())) {
            Response samlResponse = (Response) artifactResponse.getMessage();

            handleAuthnResponse(request, response, samlResponse);
        } else {
            redirectToErrorPage(response);
        }
    }

}
