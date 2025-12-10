package com.example.demo.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

public class ClearRateLimitSuccessHandler implements AuthenticationSuccessHandler {

    private final AuthenticationSuccessHandler delegate;

    public ClearRateLimitSuccessHandler(AuthenticationSuccessHandler delegate) {
        this.delegate = delegate;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication)
            throws IOException, ServletException {

        HttpSession session = request.getSession(false);
        if (session != null) {
            session.removeAttribute("LOGIN_ATTEMPTS");
            session.removeAttribute("LOGIN_ATTEMPTS_REMAINING");
            session.removeAttribute("LOGIN_BLOCK_EXPIRES_AT");
        }

        // hand over to the “real” success behaviour
        delegate.onAuthenticationSuccess(request, response, authentication);
    }
}