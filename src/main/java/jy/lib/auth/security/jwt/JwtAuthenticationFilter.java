package jy.lib.auth.security.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final ObjectMapper objectMapper = new ObjectMapper();
    private static final String TOKEN_PREFIX = "Bearer ";

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        super.setFilterProcessesUrl("/api/login");
        super.setAuthenticationManager(authenticationManager);
    }

    /**
     * 인증 요청 시 실행되는 메서드
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        log.info("JwtAuthenticationFilter ================");

        // 1. json RequestBody 에서 값 추출
        JwtLoginVo jwtLoginVo = null;
        try {
            jwtLoginVo = objectMapper.readValue(request.getInputStream(), JwtLoginVo.class);
            log.info("login request!! username={}", jwtLoginVo.getUsername());
        } catch (IOException e) {
            log.error("objectMapper.readValue() exception");
            throw new RuntimeException(e);
        }

        // 2. 시큐리티에서 사용할 인증 토큰 생성
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(jwtLoginVo.getUsername(), jwtLoginVo.getPassword());

        AuthenticationManager authenticationManager = super.getAuthenticationManager();

        // 3. AuthenticationManager에게 인증 위임 -> loadUserByUsername()으로 DB에서 데이터 확인
        return super.getAuthenticationManager().authenticate(authenticationToken);
    }

    /**
     * 인증 성공 시 실행되는 메서드
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            FilterChain chain, Authentication authResult) {

        UserDetails authenticateUserDetails = (UserDetails) authResult.getPrincipal();
        log.info("login success!! username={}", authenticateUserDetails.getUsername());
        /** (Optional) Spring Security Context에 저장
         * SecurityContext context = SecurityContextHolder.createEmptyContext();
         * context.setAuthentication(authResult);
         * SecurityContextHolder.setContext(context);
         */

        String jwt = JwtGenerator.generateJwtToken(authenticateUserDetails);

        response.addHeader(HttpHeaders.AUTHORIZATION, TOKEN_PREFIX + jwt);
    }

//    // Caused by: java.lang.IllegalArgumentException: authenticationManager must be specified
//    // UsernamePasswordAuthenticationFilter 에서 사용하는 AuthenticationManager 객체를 할당해주어야 한다.
//    public void setAuthenticationManager() {
//        super.setAuthenticationManager(authenticationManager);
//    }
}
