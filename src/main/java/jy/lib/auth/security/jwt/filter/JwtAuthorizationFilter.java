package jy.lib.auth.security.jwt.filter;

import com.auth0.jwt.interfaces.DecodedJWT;
import jy.lib.auth.entity.User;
import jy.lib.auth.security.UserDetailsImpl;
import jy.lib.auth.security.jwt.util.JwtDecoder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static jy.lib.auth.security.jwt.JwtProperties.*;


@Slf4j
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        log.info("================ JwtAuthorizationFilter ================");

        String prefixJwt = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (prefixJwt == null) {
            log.info("토큰이 없는 요청");
            chain.doFilter(request, response);
            return;
        }

        String jwt = prefixJwt.substring(TOKEN_PREFIX.length());
        log.info("jwt 값이 있는 요청, {}", jwt);

        try {
            DecodedJWT decodedJWT = JwtDecoder.validateToken(jwt);
            log.info("검증완료!!!");
            User loginUser = User.builder()
                    .userEmail(decodedJWT.getClaim(CLAIM_USER_NAME).asString())
                    .build();
            UserDetailsImpl userDetails = new UserDetailsImpl(loginUser);
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    userDetails,
                    userDetails.getPassword(),
                    userDetails.getAuthorities()
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        super.doFilterInternal(request, response, chain);
    }


}
