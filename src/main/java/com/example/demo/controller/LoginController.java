package com.example.demo.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.WebAttributes;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Principal;

@Slf4j
@Controller
public class LoginController {

    @GetMapping(value = {"/auth/login"})
    public String showLoginPage(@RequestParam(value = "error", required = false) String error,
                                Model model,
                                HttpSession session,
                                Authentication authentication,
                                HttpServletRequest request) {

        // Redirect authenticated users to home page
        // Check for non-anonymous authentication to avoid security gap
        if (authentication != null && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken)) {
            return "redirect:/home";
        }

//        if (error != null) {
//            Integer remaining = (Integer) session.getAttribute("LOGIN_ATTEMPTS_REMAINING");
//
//            String message;
//            if (remaining == null) {
//                // fallback
//                message = "Login failed. Bad credentials.";
//            } else if (remaining <= 0) {
//                message = "Too many failed attempts. Please wait a moment before trying again.";
//            } else {
//                message = "Login failed. Bad credentials, " +
//                        remaining + " attempt" + (remaining > 1 ? "s" : "") + " remaining.";
//            }
//
//            model.addAttribute("loginErrorMessage", message);
//        }

        long now = System.currentTimeMillis();

        if ("locked".equals(error)) {
            Long lockUntil = (Long) session.getAttribute("LOGIN_BLOCK_EXPIRES_AT");

            if (lockUntil != null && lockUntil > now) {
                long remainingSeconds = (lockUntil - now) / 1000;

                model.addAttribute("loginErrorMessage",
                        "Too many failed attempts. This browser is locked for a short time.");

                // for JavaScript countdown
                model.addAttribute("lockUntilEpochMillis", lockUntil);
                model.addAttribute("lockRemainingSeconds", remainingSeconds);
            } else {
                // lock already expired but URL still has ?error=locked
                model.addAttribute("loginErrorMessage",
                        "You can try logging in again now.");
            }
        } else if ("bad_credentials".equals(error)) {
            Integer remaining = (Integer) session.getAttribute("LOGIN_ATTEMPTS_REMAINING");
            String message;
            if (remaining == null) {
                message = "Login failed. Bad credentials.";
            } else if (remaining <= 0) {
                message = "Too many failed attempts. This browser is now locked.";
            } else {
                message = "Login failed. Bad credentials, " +
                        remaining + " attempt" + (remaining > 1 ? "s" : "") + " remaining.";
            }
            model.addAttribute("loginErrorMessage", message);
        }

        return "auth/login"; // Renders the Thymeleaf template (e.g., auth/login.html)
    }

    @PostMapping("/customSuccessPage")
    public String customSuccessPage(Model model, Principal principal, HttpServletRequest request) {
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");
        model.addAttribute("username", principal.getName());
        model.addAttribute("ipAddress", ipAddress);
        model.addAttribute("userAgent", userAgent);
        return "dashboard";
    }
}
