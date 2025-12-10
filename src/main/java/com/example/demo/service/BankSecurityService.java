package com.example.demo.service;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;

public interface BankSecurityService {

    void ifDifferentIpSendNotificationEmail(
            HttpServletRequest request,
            Authentication authentication
    );

    public void sendLoginNotification(String username, String ipAddress, String userAgent);
}
