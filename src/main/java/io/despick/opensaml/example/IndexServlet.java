package io.despick.opensaml.example;

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
  }

}
