package io.despick.opensaml.web;

import org.opensaml.saml.saml2.core.Artifact;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Created by DaneasaV on 13.02.2017.
 */

@WebServlet(name = "sloServlet", urlPatterns = "/sloRedirect")
public class SingleLogoutServlet extends HttpServlet {

    private static Logger LOGGER = LoggerFactory.getLogger(SingleLogoutServlet.class);

    public static final String SAML_RESPONSE_QUERY_PARAMETER = "SAMLResponse";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException,
        IOException {
        LogoutResponse logoutResponse = buildLogoutResponseFromRequest(request);

        LOGGER.info("invalidate session " + request.getSession().getId());
        request.getSession().invalidate();

        response.getWriter().append("<h1>User was logged out</h1>");
        response.getWriter().append("<p>");
        response.getWriter().append("<form action=\"/opensaml/index\" method=\"GET\"> <input type=\"submit\" value=\"Login\">");
        response.getWriter().append("</p>");
    }

    private LogoutResponse buildLogoutResponseFromRequest(HttpServletRequest request) {
        request.getParameter(SAML_RESPONSE_QUERY_PARAMETER);

        return null;
    }

}
