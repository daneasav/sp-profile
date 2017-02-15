package io.despick.opensaml.saml;

import io.despick.opensaml.error.SAMLClientException;
import io.despick.opensaml.config.IDPMetadata;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.httpclient.HttpClientBuilder;
import org.opensaml.messaging.context.InOutOperationContext;
import org.opensaml.messaging.context.MessageContext;
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
import org.opensaml.saml.saml1.binding.decoding.impl.HttpClientResponseSOAP11Decoder;
import org.opensaml.saml.saml1.binding.encoding.impl.HttpClientRequestSOAP11Encoder;
import org.opensaml.saml.saml2.core.ArtifactResolve;
import org.opensaml.saml.saml2.core.ArtifactResponse;
import org.opensaml.soap.client.http.AbstractPipelineHttpSOAPClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;

public class HTTPArtifactSenderReceiver {

    private static Logger LOGGER = LoggerFactory.getLogger(HTTPArtifactSenderReceiver.class);

    public static ArtifactResponse resolveAndReceiveArtifactResponse(HttpServletRequest request, final ArtifactResolve artifactResolve) {
        ArtifactResponse artifactResponse;

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
            soapClient.send(IDPMetadata.getArtifactResolutionService(), context);

            artifactResponse = context.getInboundMessageContext().getMessage();

            validateDestinationAndLifetime(artifactResponse, request);
            //verifyAssertionSignature(artifactResponse.getMessage());

            return artifactResponse;
        } catch (Exception e) {
            LOGGER.error("An error occurred while resolving the artifact: " + artifactResolve.toString(), e);
            throw new SAMLClientException("An error occurred while resolving the artifact", e);
        }
    }

    private static void validateDestinationAndLifetime(ArtifactResponse artifactResponse, HttpServletRequest request) {
        MessageContext<ArtifactResponse> context = new MessageContext();
        context.setMessage(artifactResponse);

        SAMLMessageInfoContext messageInfoContext = context.getSubcontext(SAMLMessageInfoContext.class, true);
        messageInfoContext.setMessageIssueInstant(artifactResponse.getIssueInstant());

        MessageLifetimeSecurityHandler lifetimeSecurityHandler = new MessageLifetimeSecurityHandler();
        lifetimeSecurityHandler.setClockSkew(300000l);
        lifetimeSecurityHandler.setMessageLifetime(300000L);
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
        } catch (ComponentInitializationException | MessageHandlerException e) {
            throw new RuntimeException(e);
        }
    }

    /*private static void verifyAssertionSignature(Assertion assertion) {
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

}
