package jy.lib.auth.security.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import jy.lib.auth.security.UserDetailsServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;

import static jy.lib.auth.security.jwt.JwtGenerator.*;

/**
 * JWT 토큰을 만들고 검증하는 등의 토큰 관련 로직 클래스
 */
@Component
@RequiredArgsConstructor
public class JwtProvider {

    private final UserDetailsServiceImpl userDetailsService;


    /**
     * JWT 토큰의 유저명 가져오기
     */
    public String getUsernameByJwtToken(String token) throws Exception {
        DecodedJWT decodedToken = JwtGenerator.validateToken(token);
        return decodedToken.getClaim(CLAIM_USER_NAME).asString();
    }

    /**
     * 인증 성공 시 권한처리를 위해 세션에 Authentication 객체 생성
     */
    public Authentication getAuthenticationTokenByUsername(String username) {
        // 유저정보 가져와서
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        // AuthenticationManager에 넘겨줄 토큰 리턴
        return new UsernamePasswordAuthenticationToken(
                userDetails, // 나중에 컨트롤러에서 DI해서 쓸 때 사용하기 편해짐
                null, // 패스워드는 모르니까 null 처리, 어차피 지금 인증하는게 아니니까!!
                userDetails.getAuthorities()
        );
    }



}
