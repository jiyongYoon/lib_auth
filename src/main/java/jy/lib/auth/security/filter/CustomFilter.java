package jy.lib.auth.security.filter;

import jy.lib.auth.security.jwt.JwtAuthenticationFilter;
import jy.lib.auth.security.jwt.JwtAuthorizationFilter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

public class CustomFilter extends AbstractHttpConfigurer<CustomFilter, HttpSecurity> {

    @Override
    public void configure(HttpSecurity builder) {
        AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);
        builder.addFilter(new JwtAuthenticationFilter(authenticationManager));
        builder.addFilter(new JwtAuthorizationFilter(authenticationManager));
    }
}
