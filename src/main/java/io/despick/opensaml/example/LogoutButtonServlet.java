package io.despick.opensaml.example;

import io.despick.opensaml.saml.HTTPRedirectSender;
import io.despick.opensaml.saml.SingleLogout;
import io.despick.opensaml.session.UserSession;
import io.despick.opensaml.session.UserSessionManager;
import org.opensaml.saml.saml2.core.LogoutRequest;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebServlet(name = "logoutServlet", urlPatterns = "/logout")
public class LogoutButtonServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        if (UserSessionManager.isUserSession(request)) {
            UserSession userSession = UserSessionManager.getUserSession(request);
            LogoutRequest logoutRequest = SingleLogout.buildLogoutRequest(userSession);

            HTTPRedirectSender.sendLogoutRequestRedirectMessage(response, logoutRequest, request.getContextPath() + "/relaystate");
        } else {
            // TODO go to default page or relay state
            //do nothing. user is not logged in
        }
    }

}
