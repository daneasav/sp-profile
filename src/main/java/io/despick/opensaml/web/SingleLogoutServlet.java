package io.despick.opensaml.web;

import io.despick.opensaml.saml.HTTPRedirectDecoder;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPRedirectDeflateDecoder;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebServlet(name = "sloServlet", urlPatterns = "/sloRedirectResponse")
public class SingleLogoutServlet extends HttpServlet {

    private static Logger LOGGER = LoggerFactory.getLogger(SingleLogoutServlet.class);

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        LogoutResponse logoutResponse = HTTPRedirectDecoder.buildLogoutResponseFromRequest(request);

        if (logoutResponse.getStatus().getStatusCode().getValue().endsWith("Success")) {
            LOGGER.info("invalidate session " + request.getSession().getId());
            request.getSession().invalidate();

            response.getWriter().append("<h1>User was logged out</h1>");
            response.getWriter().append("<p>");
            response.getWriter().append("<form action=\"/opensaml/index\" method=\"GET\"> <input type=\"submit\" value=\"Login\">");
            response.getWriter().append("</p>");
        } else {
            LOGGER.error("logout response was not success.");
        }
    }

}
