package com.example.demo.service.impl;

import com.example.demo.service.BankSecurityService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class BankSecurityServiceImpl implements BankSecurityService {

    @Override
    public void ifDifferentIpSendNotificationEmail(HttpServletRequest request, Authentication authentication) {
        String currentIp = request.getRemoteAddr();
        String username = authentication.getName();
        log.info("###########################################################");
        log.info(">> check last know ip address: {}, {} ", username, currentIp);
        log.info(">> if current ip not equal to last know ip");
        log.info(">> log and send notification");
        log.info("###########################################################");
    }

    public void sendLoginNotification(String username, String ipAddress, String userAgent) {
        // Simplified version for async notification
        log.info("Send login notification to user: {}, ipaAdress: {}, userAgent: {}", username, ipAddress, userAgent);
    }
}

