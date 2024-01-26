package jy.lib.auth.security.jwt;

import jy.lib.auth.security.UserDetailsImpl;
import jy.lib.auth.security.UserDetailsServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

/**
 * JWT 토큰을 만들고 검증하는 등의 토큰 관련 로직 클래스
 */
@Component
@RequiredArgsConstructor
public class JwtProvider implements AuthenticationProvider {

    private final UserDetailsServiceImpl userDetailsService;


    /**
     * 인증 성공 시 권한처리를 위해 세션에 Authentication 객체 생성
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 유저정보 가져와서
        UserDetailsImpl userDetails = (UserDetailsImpl) userDetailsService.loadUserByUsername(authentication.getName());

        // AuthenticationManager에 넘겨줄 토큰 리턴
        return new UsernamePasswordAuthenticationToken(
                userDetails, // 나중에 컨트롤러에서 DI해서 쓸 때 사용하기 편해짐
                null, // 패스워드는 모르니까 null 처리, 어차피 지금 인증하는게 아니니까!!
                userDetails.getAuthorities()
        );
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
