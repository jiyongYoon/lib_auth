package jy.lib.auth.security.jwt.filter;

import com.auth0.jwt.interfaces.DecodedJWT;
import jy.lib.auth.entity.User;
import jy.lib.auth.security.UserDetailsImpl;
import jy.lib.auth.security.jwt.JwtProperties;
import jy.lib.auth.security.jwt.RefreshTokenStorage;
import jy.lib.auth.security.jwt.dto.GenerateJwtRequest;
import jy.lib.auth.security.jwt.util.JwtDecoder;
import jy.lib.auth.security.jwt.util.JwtGenerator;
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
    private final RefreshTokenStorage refreshTokenStorage;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, RefreshTokenStorage refreshTokenStorage) {
        super(authenticationManager);
        this.refreshTokenStorage = refreshTokenStorage;
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

        // 서명 검사
        DecodedJWT decodedJWT = JwtDecoder.validateSignature(jwt);
        // 유효기간 검사
        boolean isExpired = JwtDecoder.isExpired(jwt);
        if (isExpired) {
            log.info("서명은 유효하나 토큰이 만료됨");
            String requestRefreshToken = request.getHeader(REFRESH_TOKEN_HEADER);
            if (requestRefreshToken == null) {
                throw new RuntimeException(
                        "Access Token의 유효기간이 만료되었으니 가지고있는 RefreshToken을 'Refresh_Token' Header에 넣어서 보내주세요.");
            } else {
                String serverRefreshToken = refreshTokenStorage.findRefreshTokenByAccessToken(jwt)
                        .orElseThrow(() -> new RuntimeException(
                                "해당 Access Token에 대한 Refresh Token 발급이 완료되었습니다. 새로 로그인하세요."));
                JwtDecoder.validateSignature(requestRefreshToken);
                if (requestRefreshToken.equals(serverRefreshToken)) {
                    refreshTokenStorage.removeToken(jwt);

                    String newAccessToken = JwtGenerator.generateAccessToken(GenerateJwtRequest.builder()
                            .userId(decodedJWT.getClaim(CLAIM_USER_ID).asLong())
                            .username(decodedJWT.getClaim(CLAIM_USER_NAME).asString())
                            .build());
                    String newRefreshToken = JwtGenerator.generateRefreshToken();

                    refreshTokenStorage.saveAccessAndRefreshToken(newAccessToken, newRefreshToken);

                    log.info("access & refresh token 재발급 완료!");

                    response.addHeader(HttpHeaders.AUTHORIZATION, TOKEN_PREFIX + newAccessToken);
                    response.addHeader(JwtProperties.REFRESH_TOKEN_HEADER, newRefreshToken);
                } else {
                    throw new RuntimeException("말도 안됨. 서버 내부 로직 오류일수밖에 없음.");
                }
            }
        } else {
            log.info("서명은 유효하며 토큰이 만료되지 않음");
        }

        injectAuthenticationInSecurityContext(decodedJWT);

        super.doFilterInternal(request, response, chain);
    }

    private void injectAuthenticationInSecurityContext(DecodedJWT decodedJWT) {
        User loginUser = User.builder()
                .userId(decodedJWT.getClaim(CLAIM_USER_ID).asLong())
                .userEmail(decodedJWT.getClaim(CLAIM_USER_NAME).asString())
                .build();
        UserDetailsImpl userDetails = new UserDetailsImpl(loginUser);
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                userDetails,
                userDetails.getPassword(),
                userDetails.getAuthorities()
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
