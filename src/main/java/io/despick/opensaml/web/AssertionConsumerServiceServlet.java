package io.despick.opensaml.web;

import io.despick.opensaml.init.IDPMetadata;
import io.despick.opensaml.saml.HTTPArtifactSender;
import io.despick.opensaml.saml.SAMLUtil;
import io.despick.opensaml.saml.session.UserSession;
import org.joda.time.DateTime;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.impl.XSAnyImpl;
import org.opensaml.saml.saml2.core.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

@WebServlet(name = "acsServlet", urlPatterns = "/acsArtifact")
public class AssertionConsumerServiceServlet extends HttpServlet {

    private static Logger LOGGER = LoggerFactory.getLogger(AssertionConsumerServiceServlet.class);

    public static final String SAMLART_QUERY_PARAMETER = "SAMLart";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
        LOGGER.info("Artifact received");
        Artifact artifact = buildArtifact(request.getParameter(SAMLART_QUERY_PARAMETER));
        LOGGER.info("Artifact: " + artifact.getArtifact());

        ArtifactResolve artifactResolve = buildArtifactResolve(artifact);
        LOGGER.info("Sending ArtifactResolve");

        ArtifactResponse artifactResponse = HTTPArtifactSender.resolveAndReceiveArtifactResponse(request, artifactResolve);

        UserSession userSession = new UserSession();
        if (Response.DEFAULT_ELEMENT_LOCAL_NAME.equals(artifactResponse.getMessage().getElementQName().getLocalPart())) {
            if (artifactResponse.getMessage().hasChildren()) {
                // get the first one since the IDP only sends one assertion
                Response samlResponse = (Response) artifactResponse.getMessage();

                //TODO check the number of assertions
                if (samlResponse.getAssertions().size() == 1) {
                    Assertion assertion = samlResponse.getAssertions().get(0);

                    // remove nameid from the dom
                    assertion.getSubject().getNameID().detach();

                    userSession.setSamlNameID(assertion.getSubject().getNameID());

                    for (AttributeStatement attributeStatement : assertion.getAttributeStatements()) {
                        for (Attribute attribute : attributeStatement.getAttributes()) {
                            List<XMLObject> attributeValues = attribute.getAttributeValues();

                            if (!attributeValues.isEmpty()) {
                                switch (attribute.getName()) {
                                    case "SSOToken":
                                        userSession.setSsoToken(getAttributeValue(attributeValues.get(0)));
                                        break;
                                    case "AuthLevel":
                                        userSession.setAuthLevel(Integer.parseInt(getAttributeValue(attributeValues.get(0))));
                                        break;
                                    case "HMGUSERID":
                                        userSession.setUserID(getAttributeValue(attributeValues.get(0)));
                                        break;
                                    case "huid":
                                        userSession.setHssiID(getAttributeValue(attributeValues.get(0)));
                                        break;
                                    case "Salutation":
                                        userSession.setSalutation(getAttributeValue(attributeValues.get(0)));
                                        break;
                                    case "FirstName":
                                        userSession.setFirstName(getAttributeValue(attributeValues.get(0)));
                                        break;
                                    case "LastName":
                                        userSession.setLastName(getAttributeValue(attributeValues.get(0)));
                                        break;
                                    case "Email":
                                        userSession.setEmail(getAttributeValue(attributeValues.get(0)));
                                        break;
                                }
                            }
                        }
                    }
                    // TODO only one authn statement is expected
                    if (assertion.getAuthnStatements().size() == 1) {
                        userSession.setSamlSessionIndex(assertion.getAuthnStatements().get(0).getSessionIndex());
                    }
                }

            }
        }

        request.getSession().setAttribute(AuthFilter.AUTHENTICATED_SESSION_ATTRIBUTE, userSession);

        try {
            response.sendRedirect("/opensaml/index");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private Artifact buildArtifact(String artifactID) {
        Artifact artifact = SAMLUtil.buildSAMLObject(Artifact.class);
        artifact.setArtifact(artifactID);
        return artifact;
    }

    private ArtifactResolve buildArtifactResolve(final Artifact artifact) {
        ArtifactResolve artifactResolve = SAMLUtil.buildSAMLObject(ArtifactResolve.class);
        artifactResolve.setIssuer(SAMLUtil.buildSPIssuer());
        artifactResolve.setIssueInstant(new DateTime());
        artifactResolve.setID(SAMLUtil.getRandomID());
        artifactResolve.setDestination(IDPMetadata.getArtifactResolutionService());
        artifactResolve.setArtifact(artifact);

        return artifactResolve;
    }

    private String getAttributeValue(XMLObject attributeValue) {
        return attributeValue == null ? null :
            attributeValue instanceof XSString ? getStringAttributeValue((XSString) attributeValue) :
                attributeValue instanceof XSAnyImpl ? getAnyAttributeValue((XSAnyImpl) attributeValue) :
                    attributeValue.toString();
    }

    private String getStringAttributeValue(XSString attributeValue) {
        return attributeValue.getValue();
    }

    private String getAnyAttributeValue(XSAnyImpl attributeValue) {
        return attributeValue.getTextContent();
    }

}
