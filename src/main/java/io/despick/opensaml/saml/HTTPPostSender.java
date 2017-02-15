package io.despick.opensaml.saml;

import io.despick.opensaml.error.SAMLClientException;
import io.despick.opensaml.init.IDPMetadata;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.velocity.SLF4JLogChute;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.messaging.context.SAMLBindingContext;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPPostEncoder;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletResponse;
import java.util.Properties;

public class HTTPPostSender {

    public static final Logger LOGGER = LoggerFactory.getLogger(HTTPPostSender.class);

    public static void sendAuthnRequestPostMessage(HttpServletResponse response, AuthnRequest authnRequest) {
        sendPostMessage(response, authnRequest, IDPMetadata.getIDPSSOServiceEndpointByBinding(SAMLConstants.SAML2_POST_BINDING_URI));
    }

    public static void sendLogoutRequestPostMessage(HttpServletResponse response, LogoutRequest logoutRequest) {
        sendPostMessage(response, logoutRequest, IDPMetadata.getIDPSLOServiceEndpointByBinding(SAMLConstants.SAML2_POST_BINDING_URI));
    }

    public static void sendLogoutResponsePostMessage(HttpServletResponse response, LogoutResponse logoutResponse) {
        sendPostMessage(response, logoutResponse, IDPMetadata.getIDPSLOServiceEndpointByBinding(SAMLConstants.SAML2_POST_BINDING_URI));
    }

    private static void sendPostMessage(HttpServletResponse response, SAMLObject message, Endpoint endpoint) {
        MessageContext<SAMLObject> context = new MessageContext();
        context.setMessage(message);

        SAMLPeerEntityContext peerEntityContext = context.getSubcontext(SAMLPeerEntityContext.class, true);

        /*SAMLBindingContext bindingContext = context.getSubcontext(SAMLBindingContext.class, true);
        bindingContext.setRelayState("");*/

        SAMLEndpointContext endpointContext = peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);
        endpointContext.setEndpoint(endpoint);

        HTTPPostEncoder encoder = new HTTPPostEncoder();
        encoder.setVelocityEngine(getVelocityEngine());
        encoder.setMessageContext(context);
        encoder.setHttpServletResponse(response);

        try {
            encoder.initialize();
        } catch (ComponentInitializationException e) {
            throw new RuntimeException(e);
        }

        LOGGER.info("Redirecting to IDP");
        try {
            encoder.encode();
        } catch (MessageEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    public static VelocityEngine getVelocityEngine() {

        try {
            final Properties props =
                new Properties(net.shibboleth.utilities.java.support.velocity.VelocityEngine.getDefaultProperties());
            props.setProperty(RuntimeConstants.INPUT_ENCODING, "UTF-8");
            props.setProperty(RuntimeConstants.OUTPUT_ENCODING, "UTF-8");
            props.setProperty(RuntimeConstants.RESOURCE_LOADER, "classpath");
            props.setProperty(RuntimeConstants.RUNTIME_LOG_LOGSYSTEM_CLASS, SLF4JLogChute.class.getName());

            final VelocityEngine velocityEngine = net.shibboleth.utilities.java.support.velocity.VelocityEngine
                    .newVelocityEngine(props);
            return velocityEngine;
        } catch (final Exception e) {
            throw new SAMLClientException("Error configuring velocity", e);
        }

    }

}
