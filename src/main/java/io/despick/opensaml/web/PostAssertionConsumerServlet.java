package io.despick.opensaml.web;

import io.despick.opensaml.saml.HTTPPostDecoder;
import org.opensaml.saml.saml2.core.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(name = "postACSServlet", urlPatterns = "/acsPost")
public class PostAssertionConsumerServlet extends AbstractSAMLClientServlet {

    private static Logger LOGGER = LoggerFactory.getLogger(PostAssertionConsumerServlet.class);

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) {
        Response samlResponse = HTTPPostDecoder.buildResponseFromRequest(request);

        handleAuthnResponse(request, response, samlResponse);
    }

}
