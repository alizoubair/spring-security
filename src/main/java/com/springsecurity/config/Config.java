package com.springsecurity.config;

import com.springsecurity.filters.AuthenticationLoggingFilter;
import com.springsecurity.filters.RequestValidationFilter;
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

    public Config(CustomAuthenticationProvider customAuthenticationProvider) {
        this.authenticationProvider = customAuthenticationProvider;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.addFilterBefore(
                        new RequestValidationFilter(),
                        BasicAuthenticationFilter.class)
                    .addFilterAfter(
                            new AuthenticationLoggingFilter(),
                            BasicAuthenticationFilter.class
                    )
                    .authorizeRequests()
                            .anyRequest()
                                    .permitAll();

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
