package io.despick.opensaml.example;

import io.despick.opensaml.session.UserSessionManager;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebServlet(name = "relayStateServlet", urlPatterns = "/relaystate")
public class RelayStateServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        response.getWriter().append("<h1> You are the Relaystate page</h1>");
        response.getWriter().append("You are " + (UserSessionManager.isUserSession(request) ? "" : "not") + " authenticated!");
    }

}
