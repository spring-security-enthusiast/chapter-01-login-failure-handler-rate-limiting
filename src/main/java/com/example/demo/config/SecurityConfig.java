package com.example.demo.config;

import com.example.demo.filter.RateLimitFilter;
import com.example.demo.handler.ClearRateLimitSuccessHandler;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.security.autoconfigure.web.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.time.Duration;

@Slf4j
@RequiredArgsConstructor
@EnableWebSecurity(debug = true)
@Configuration
public class SecurityConfig {

    // Session attribute keys
    public static final String LOGIN_ATTEMPTS = "LOGIN_ATTEMPTS";
    public static final String LOGIN_BLOCK_EXPIRES_AT = "LOGIN_BLOCK_EXPIRES_AT";
    public static final String LOGIN_ATTEMPTS_REMAINING = "LOGIN_ATTEMPTS_REMAINING";

    public static final int MAX_ATTEMPTS = 3;
    public static final long BLOCK_MILLIS = 60_000L; // 1 minute


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, RateLimitFilter rateLimitFilter) throws Exception {
        http
            .addFilterBefore(rateLimitFilter, UsernamePasswordAuthenticationFilter.class)
            .csrf(Customizer.withDefaults())
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers(
                        PathRequest.toStaticResources().atCommonLocations()
                ).permitAll()
                .requestMatchers("/auth/**").permitAll()
                .anyRequest().authenticated()
            )
            .formLogin(formLogin -> formLogin
                .loginPage("/auth/login")
                .loginProcessingUrl("/auth/login_processing")
                .successHandler(loginSuccessHandler())
                .failureHandler(rateLimitingFailureHandler())
                .permitAll()
            )
            .logout(LogoutConfigurer::permitAll);

        http.addFilterBefore(rateLimitFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * Implements basic brute-force protection by tracking failed login attempts
     * in the HTTP session (i.e. per browser session, not per user account).
     */
    @Bean
    public AuthenticationFailureHandler rateLimitingFailureHandler() {
        return (request, response, exception) -> {
            HttpSession session = request.getSession(true);
            long now = System.currentTimeMillis();

            // ---- Configuration ----
            int maxAttempts = 3;
            long blockMillis = 60_000L; // 1 minute

            // ---- Step 1: Increment attempt counter ----
            Integer attempts = (Integer) session.getAttribute("LOGIN_ATTEMPTS");
            attempts = (attempts == null) ? 1 : attempts + 1;
            session.setAttribute("LOGIN_ATTEMPTS", attempts);

            int remaining = Math.max(0, maxAttempts - attempts);
            session.setAttribute("LOGIN_ATTEMPTS_REMAINING", remaining);

            // ---- Step 2: Check threshold & apply temporary block ----
            if (attempts >= maxAttempts) {
                long expiresAt = now + blockMillis;
                session.setAttribute("LOGIN_BLOCK_EXPIRES_AT", expiresAt);

                session.setAttribute(
                        WebAttributes.AUTHENTICATION_EXCEPTION,
                        new LockedException(
                                "Too many failed attempts. Login is temporarily locked."
                        )
                );

                response.sendRedirect("/auth/login?error=locked");
                return;
            }

            // ---- Step 3: Normal bad credentials flow ----
            session.setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, exception);
            response.sendRedirect("/auth/login?error=bad_credentials");
        };
    }


    /**
     * Extracts a client IP address for logging purposes.
     *
     * Note: This is a simplified implementation for demos.
     * In production, rely on your infrastructure's proxy configuration
     * (e.g. Spring's ForwardedHeaderFilter + trusted proxies).
     */
    private String getClientIP(HttpServletRequest request) {
        String header = request.getHeader("X-Forwarded-For");
        if (header != null && !header.isBlank() && !"unknown".equalsIgnoreCase(header)) {
            // Take the first IP in the list (original client)
            return header.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }


    /**
     * Clears rate limiting counters after successful authentication.
     * This ensures users can retry immediately after a successful login.
     *
     * Note: For simplicity, this handler always redirects to "/home"
     * instead of the originally requested URL.
     */
    @Bean
    public AuthenticationSuccessHandler loginSuccessHandler() {
        SimpleUrlAuthenticationSuccessHandler base =
                new SimpleUrlAuthenticationSuccessHandler("/home");
        return new ClearRateLimitSuccessHandler(base);
    }

}
