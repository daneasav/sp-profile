package io.despick.opensaml.web;

import io.despick.opensaml.init.SamlMetadata;
import io.despick.opensaml.saml.SingleSignOn;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPRedirectDeflateEncoder;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

/**
 * Created by DaneasaV on 21.11.2016.
 */

@WebFilter(displayName = "authFilter", urlPatterns = "/index")
public class AuthFilter implements Filter {

  public static final Logger LOGGER = LoggerFactory.getLogger(AuthFilter.class);

  public static final String AUTHENTICATED_SESSION_ATTRIBUTE = "user.session.attribute";

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {

  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
      throws IOException, ServletException {

    HttpServletRequest httpServletRequest = (HttpServletRequest) request;
    HttpServletResponse httpServletResponse = (HttpServletResponse) response;

    if (httpServletRequest.getSession().getAttribute(AUTHENTICATED_SESSION_ATTRIBUTE) != null) {
      filterChain.doFilter(request, response);
    } else {
      AuthnRequest authnRequest = new SingleSignOn().buildAuthnRequest();

      MessageContext context = new MessageContext();
      context.setMessage(authnRequest);

      SAMLPeerEntityContext peerEntityContext = context.getSubcontext(SAMLPeerEntityContext.class, true);

      SAMLEndpointContext endpointContext = peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);
      endpointContext.setEndpoint(getIDPEndpointByBinding(
          SamlMetadata.idpDescriptor.getIDPSSODescriptor(SAMLConstants.SAML20P_NS),
          SAMLConstants.SAML2_REDIRECT_BINDING_URI));

      HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();

      encoder.setMessageContext(context);
      encoder.setHttpServletResponse(httpServletResponse);

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
  }

  private Endpoint getIDPEndpointByBinding(IDPSSODescriptor idpssoDescriptor, String binding) {
    List<SingleSignOnService> singleSignOnServices = idpssoDescriptor.getSingleSignOnServices();

    for (SingleSignOnService ssoService : singleSignOnServices) {
      if (ssoService.getBinding().equals(binding)) {
        return ssoService;
      }
    }

    // TODO: return fallback binding
    return null;
  }

  @Override
  public void destroy() {

  }
}
