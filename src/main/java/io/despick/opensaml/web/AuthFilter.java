package io.despick.opensaml.web;

import io.despick.opensaml.init.SamlMetadata;
import io.despick.opensaml.saml.HTTPRedirectSender;
import io.despick.opensaml.saml.SingleSignOn;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

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

      HTTPRedirectSender.sendAuthnRequestRedirectMessage(httpServletResponse, authnRequest,
          SamlMetadata.idpDescriptor.getIDPSSODescriptor(SAMLConstants.SAML20P_NS), SAMLConstants.SAML2_REDIRECT_BINDING_URI);
    }
  }

  @Override
  public void destroy() {

  }
}
