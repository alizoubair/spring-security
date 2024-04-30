package com.springsecurity.config;

import com.springsecurity.filters.AuthenticationLoggingFilter;
import com.springsecurity.filters.RequestValidationFilter;
import com.springsecurity.filters.StaticKeyAuthenticationFilter;
import com.springsecurity.security.CustomAuthenticationProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.sql.DataSource;

@Configuration
public class Config {

    private final CustomAuthenticationProvider authenticationProvider;
    private final StaticKeyAuthenticationFilter filter;

    public Config(CustomAuthenticationProvider customAuthenticationProvider, StaticKeyAuthenticationFilter filter) {
        this.authenticationProvider = customAuthenticationProvider;
        this.filter = filter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.addFilterAt(
                        filter,
                        BasicAuthenticationFilter.class)
                    .authorizeHttpRequests(c -> c.anyRequest().permitAll());

        return httpSecurity.build();
    }

    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        return new JdbcUserDetailsManager(dataSource);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
}
