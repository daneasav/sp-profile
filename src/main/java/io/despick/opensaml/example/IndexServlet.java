package io.despick.opensaml.example;

import io.despick.opensaml.saml.UserSession;
import io.despick.opensaml.web.AuthFilter;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Created by DaneasaV on 21.11.2016.
 */

@WebServlet(name = "indexServlet", urlPatterns = "/index")
public class IndexServlet extends HttpServlet {

  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    response.setContentType("text/html");
    response.getWriter().append("<h1>You are now at the requested resource</h1>");
    response.getWriter().append("This is the protected resource. You are authenticated");

    UserSession userSession = (UserSession) request.getSession().getAttribute(AuthFilter.AUTHENTICATED_SESSION_ATTRIBUTE);
    response.getWriter().append("<p>");
    response.getWriter().append("SAML NameID: " + userSession.getSamlNameID().getValue());
    response.getWriter().append("<br/>");
    response.getWriter().append("SAML Session ID: " + userSession.getSamlSessionIndex());
    response.getWriter().append("<br/>");
    response.getWriter().append("SSOToken: " + userSession.getSsoToken());
    response.getWriter().append("<br/>");
    response.getWriter().append("Auth Level: " + userSession.getAuthLevel());
    response.getWriter().append("<br/>");
    response.getWriter().append("UserID: " + userSession.getUserID());
    response.getWriter().append("<br/>");
    response.getWriter().append("HssiID: " + userSession.getHssiID());
    response.getWriter().append("<br/>");
    response.getWriter().append("Salutation: " + userSession.getSalutation());
    response.getWriter().append("<br/>");
    response.getWriter().append("First Name: " + userSession.getFirstName());
    response.getWriter().append("<br/>");
    response.getWriter().append("Last Name: " + userSession.getLastName());
    response.getWriter().append("<br/>");
    response.getWriter().append("Email: " + userSession.getEmail());
    response.getWriter().append("</p>");

    response.getWriter().append("<p>");
    response.getWriter().append("<form action=\"/opensaml/logout\" method=\"GET\"> <input type=\"submit\" value=\"Logout\">");
    response.getWriter().append("</p>");
  }

}
