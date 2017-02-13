package io.despick.opensaml.web;

import io.despick.opensaml.init.SamlMetadata;
import io.despick.opensaml.saml.SAMLUtil;
import io.despick.opensaml.saml.UserSession;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.httpclient.HttpClientBuilder;
import org.joda.time.DateTime;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.impl.XSAnyImpl;
import org.opensaml.messaging.context.InOutOperationContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.messaging.handler.MessageHandler;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.messaging.handler.impl.BasicMessageHandlerChain;
import org.opensaml.messaging.pipeline.httpclient.BasicHttpClientMessagePipeline;
import org.opensaml.messaging.pipeline.httpclient.HttpClientMessagePipeline;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.binding.security.impl.MessageLifetimeSecurityHandler;
import org.opensaml.saml.common.binding.security.impl.ReceivedEndpointSecurityHandler;
import org.opensaml.saml.common.binding.security.impl.SAMLOutboundProtocolMessageSigningHandler;
import org.opensaml.saml.common.messaging.context.SAMLMessageInfoContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml1.binding.decoding.impl.HttpClientResponseSOAP11Decoder;
import org.opensaml.saml.saml1.binding.encoding.impl.HttpClientRequestSOAP11Encoder;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.metadata.ArtifactResolutionService;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;

import org.opensaml.soap.client.http.AbstractPipelineHttpSOAPClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by DaneasaV on 10.02.2017.
 */

@WebServlet(name = "acsServlet", urlPatterns = "/acsArtifact")
public class AssertionConsumerServiceServlet extends HttpServlet {

    private static Logger LOGGER = LoggerFactory.getLogger(AssertionConsumerServiceServlet.class);

    public static final String SAMLART_QUERY_PARAMETER = "SAMLart";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
        LOGGER.info("Artifact received");
        Artifact artifact = buildArtifactFromRequest(request);
        LOGGER.info("Artifact: " + artifact.getArtifact());

        ArtifactResolve artifactResolve = buildArtifactResolve(artifact);
        LOGGER.info("Sending ArtifactResolve");

        ArtifactResponse artifactResponse = sendAndReceiveArtifactResolve(artifactResolve);
        validateDestinationAndLifetime(artifactResponse, request);
        //verifyAssertionSignature(artifactResponse.getMessage());

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

    private Artifact buildArtifactFromRequest(final HttpServletRequest request) {
        Artifact artifact = SAMLUtil.buildSAMLObject(Artifact.class);
        artifact.setArtifact(request.getParameter(SAMLART_QUERY_PARAMETER));
        return artifact;
    }

    private ArtifactResolve buildArtifactResolve(final Artifact artifact) {
        Issuer issuer = SAMLUtil.buildSAMLObject(Issuer.class);
        issuer.setValue(SamlMetadata.spDescriptor.getEntityID());

        ArtifactResolve artifactResolve = SAMLUtil.buildSAMLObject(ArtifactResolve.class);
        artifactResolve.setIssuer(issuer);
        artifactResolve.setIssueInstant(new DateTime());
        artifactResolve.setID(SAMLUtil.secureRandomIdGenerator.generateIdentifier());
        artifactResolve.setDestination(
            getIDPArtifactResolutionService(SamlMetadata.idpDescriptor.getIDPSSODescriptor(SAMLConstants.SAML20P_NS)));
        artifactResolve.setArtifact(artifact);

        return artifactResolve;
    }

    private String getIDPArtifactResolutionService(IDPSSODescriptor idpssoDescriptor) {
        ArtifactResolutionService artifactResolutionService = idpssoDescriptor.getDefaultArtifactResolutionService();

        if (artifactResolutionService == null) {
            artifactResolutionService = idpssoDescriptor.getArtifactResolutionServices().get(0);

            // TODO: fail if nothing is found, also maybe check for binding
        }

        return artifactResolutionService.getLocation();
    }

    private ArtifactResponse sendAndReceiveArtifactResolve(final ArtifactResolve artifactResolve) {
        try {
            MessageContext<ArtifactResolve> artifactMessageContext = new MessageContext<>();
            artifactMessageContext.setMessage(artifactResolve);

            InOutOperationContext<ArtifactResponse, ArtifactResolve> context = new ProfileRequestContext<>();
            context.setOutboundMessageContext(artifactMessageContext);

            HttpClientBuilder clientBuilder = new HttpClientBuilder();

            AbstractPipelineHttpSOAPClient<SAMLObject, SAMLObject> soapClient = new AbstractPipelineHttpSOAPClient() {
                @Override
                protected HttpClientMessagePipeline<SAMLObject, SAMLObject> newPipeline() {
                    HttpClientRequestSOAP11Encoder encoder = new HttpClientRequestSOAP11Encoder();
                    HttpClientResponseSOAP11Decoder decoder = new HttpClientResponseSOAP11Decoder();

                    BasicHttpClientMessagePipeline<SAMLObject, SAMLObject> pipeline =
                        new BasicHttpClientMessagePipeline(encoder, decoder);
                    pipeline.setOutboundPayloadHandler(new SAMLOutboundProtocolMessageSigningHandler());

                    return pipeline;
                }
            };

            soapClient.setHttpClient(clientBuilder.buildClient());
            soapClient.send(getIDPArtifactResolutionService(
                SamlMetadata.idpDescriptor.getIDPSSODescriptor(SAMLConstants.SAML20P_NS)), context);

            return context.getInboundMessageContext().getMessage();
        } catch (SecurityException e) {
            throw new RuntimeException(e);
        } catch (ComponentInitializationException e) {
            throw new RuntimeException(e);
        } catch (MessageEncodingException e) {
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void validateDestinationAndLifetime(ArtifactResponse artifactResponse, HttpServletRequest request) {
        MessageContext<ArtifactResponse> context = new MessageContext();
        context.setMessage(artifactResponse);

        SAMLMessageInfoContext messageInfoContext = context.getSubcontext(SAMLMessageInfoContext.class, true);
        messageInfoContext.setMessageIssueInstant(artifactResponse.getIssueInstant());

        MessageLifetimeSecurityHandler lifetimeSecurityHandler = new MessageLifetimeSecurityHandler();
        lifetimeSecurityHandler.setClockSkew(1000);
        lifetimeSecurityHandler.setMessageLifetime(2000);
        lifetimeSecurityHandler.setRequiredRule(true);

        ReceivedEndpointSecurityHandler receivedEndpointSecurityHandler = new ReceivedEndpointSecurityHandler();
        receivedEndpointSecurityHandler.setHttpServletRequest(request);

        List<MessageHandler<ArtifactResponse>> handlers = new ArrayList<>();
        handlers.add(lifetimeSecurityHandler);
        handlers.add(receivedEndpointSecurityHandler);

        BasicMessageHandlerChain<ArtifactResponse> handlerChain = new BasicMessageHandlerChain<>();
        handlerChain.setHandlers(handlers);

        try {
            handlerChain.initialize();
            handlerChain.doInvoke(context);
        } catch (ComponentInitializationException e) {
            throw new RuntimeException(e);
        } catch (MessageHandlerException e) {
            throw new RuntimeException(e);
        }
    }


    /*private void verifyAssertionSignature(Assertion assertion) {
        if (!assertion.isSigned()) {
            throw new RuntimeException("The SAML Assertion was not signed");
        }

        try {
            SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
            profileValidator.validate(assertion.getSignature());

            SignatureValidator.validate(assertion.getSignature(), );

            LOGGER.info("SAML Assertion signature verified");
        } catch (SignatureException e) {
            e.printStackTrace();
        }
    }*/

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
