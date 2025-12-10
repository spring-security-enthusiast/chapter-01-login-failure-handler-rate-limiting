package com.example.demo.config;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;

@Configuration
public class UserConfig {

    @Bean
    public PasswordEncoder bcryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    UserDetailsManager manager() {
        return new InMemoryUserDetailsManager();
    }

    @Bean
    InitializingBean initializer(UserDetailsManager manager) {
        return () -> {
            UserDetails user = User.withUsername("user")
                    .passwordEncoder(bcryptPasswordEncoder()::encode)
                    .password("password")
                    .roles("USER")
                    .build();

            UserDetails admin = User.withUsername("admin")
                    .passwordEncoder(bcryptPasswordEncoder()::encode)
                    .password("password")
                    .roles("ADMIN")
                    .build();

            manager.createUser(user);
            manager.createUser(admin);
        };
    }
}
