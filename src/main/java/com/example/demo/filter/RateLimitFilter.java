package com.example.demo.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class RateLimitFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain)
            throws ServletException, IOException {

        if ("/auth/login_processing".equals(request.getServletPath())) {
            HttpSession session = request.getSession(false);
            if (session != null) {
                Long blockExpiresAt = (Long) session.getAttribute("LOGIN_BLOCK_EXPIRES_AT");
                long now = System.currentTimeMillis();

                if (blockExpiresAt != null && blockExpiresAt > now) {
                    response.sendRedirect(request.getContextPath() + "/auth/login?error=locked");
                    return;
                }

                if (blockExpiresAt != null && blockExpiresAt <= now) {
                    session.removeAttribute("LOGIN_BLOCK_EXPIRES_AT");
                    session.removeAttribute("LOGIN_ATTEMPTS");
                    session.removeAttribute("LOGIN_ATTEMPTS_REMAINING");
                }
            }
        }

        chain.doFilter(request, response);
    }
}