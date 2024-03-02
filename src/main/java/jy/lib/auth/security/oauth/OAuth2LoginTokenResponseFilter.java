package jy.lib.auth.security.oauth;

import static jy.lib.auth.security.jwt.JwtProperties.TOKEN_PREFIX;

import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import jy.lib.auth.security.jwt.JwtProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;

@Slf4j
public class OAuth2LoginTokenResponseFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
        throws IOException, ServletException {

        log.info("oauth-jwt redirect!");

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        if (httpRequest.getRequestURI().startsWith("/api/oauth-jwt")) {
            String accessToken = request.getParameter("access_token");
            String refreshToken = request.getParameter("refresh_token");

            httpResponse.addHeader(HttpHeaders.AUTHORIZATION, TOKEN_PREFIX + accessToken);
            httpResponse.addHeader(JwtProperties.REFRESH_TOKEN_HEADER, refreshToken);
        }

        chain.doFilter(request, response);
    }
}
