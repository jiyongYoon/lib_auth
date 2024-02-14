package jy.lib.auth.security.filter;

import jy.lib.auth.security.jwt.RefreshTokenStorage;
import jy.lib.auth.security.jwt.filter.JwtAuthenticationFilter;
import jy.lib.auth.security.jwt.filter.JwtAuthorizationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

@RequiredArgsConstructor
public class CustomFilter extends AbstractHttpConfigurer<CustomFilter, HttpSecurity> {

    private final RefreshTokenStorage refreshTokenStorage;

    @Override
    public void configure(HttpSecurity builder) {
        AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);
        builder.addFilter(new JwtAuthenticationFilter(authenticationManager, refreshTokenStorage));
        builder.addFilter(new JwtAuthorizationFilter(authenticationManager, refreshTokenStorage));
    }
}
