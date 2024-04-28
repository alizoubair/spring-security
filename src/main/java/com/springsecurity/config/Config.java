package com.springsecurity.config;

import com.springsecurity.security.CustomAuthenticationProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class Config {

    private final CustomAuthenticationProvider authenticationProvider;

    public Config(CustomAuthenticationProvider customAuthenticationProvider) {
        this.authenticationProvider = customAuthenticationProvider;
    }

    @Bean
    public SecurityFilterChain configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.httpBasic(Customizer.withDefaults());
        httpSecurity.authenticationProvider(authenticationProvider);
        httpSecurity.authorizeHttpRequests(
                c -> c.anyRequest().authenticated()
        );

        return httpSecurity.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
}
