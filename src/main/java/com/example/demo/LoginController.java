package com.example.demo;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import java.io.IOException;

@Controller
public class LoginController {

    @RequestMapping("/fgn")
    public void login(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String tenant = "okta";
        tenant   = request.getParameter("tenantId");
        response.sendRedirect("/saml2/authenticate/"+tenant);
    }

}
