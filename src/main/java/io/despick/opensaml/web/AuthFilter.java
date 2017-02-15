package io.despick.opensaml.web;

import io.despick.opensaml.saml.HTTPRedirectSender;
import io.despick.opensaml.saml.SingleSignOn;
import io.despick.opensaml.session.UserSessionManager;
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

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
  }

  @Override
  public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
      throws IOException, ServletException {

    HttpServletRequest request = (HttpServletRequest) servletRequest;
    HttpServletResponse response = (HttpServletResponse) servletResponse;

    if (UserSessionManager.isUserSession(request)) {
      filterChain.doFilter(servletRequest, servletResponse);
    } else {
      AuthnRequest authnRequest = SingleSignOn.buildAuthnRequest();

      HTTPRedirectSender.sendAuthnRequestRedirectMessage(response, authnRequest, request.getContextPath() + "/relaystate");
    }
  }

  @Override
  public void destroy() {
  }

}
