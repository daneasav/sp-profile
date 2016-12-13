package io.despick.opensaml.filter;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPRedirectDeflateEncoder;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Created by DaneasaV on 21.11.2016.
 */

@WebFilter(displayName = "authFilter", urlPatterns = "/index")
public class AuthFilter implements Filter {

  public static final Logger LOGGER = LoggerFactory.getLogger(AuthFilter.class);

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {

  }

  @Override
  public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
      throws IOException, ServletException {
    MessageContext context = new MessageContext();
    context.setMessage(authnRequest);

    Endpoint

    SAMLPeerEntityContext peerEntityContext = context.getSubcontext(SAMLPeerEntityContext.class, true);
    SAMLEndpointContext endpointContext = peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);
    endpointContext.setEndpoint(idpEndpoint);

    HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
    encoder.setMessageContext(context);
    encoder.setHttpServletResponse((HttpServletResponse) servletResponse);

    try {
      encoder.initialize();
      encoder.encode();
    } catch (ComponentInitializationException e) {
      LOGGER.error("Encoder init error", e);
    } catch (MessageEncodingException e) {
      LOGGER.error("Encoder error" ,e);
    } finally {
      filterChain.doFilter(servletRequest, servletResponse);
    }
  }

  @Override
  public void destroy() {

  }
}
