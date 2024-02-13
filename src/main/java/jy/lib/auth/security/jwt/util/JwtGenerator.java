package jy.lib.auth.security.jwt.util;

import com.auth0.jwt.JWT;
import jy.lib.auth.security.UserDetailsImpl;

import javax.annotation.PostConstruct;
import java.util.Base64;
import java.util.Date;

import static jy.lib.auth.security.jwt.JwtProperties.*;

public class JwtGenerator {


    /**
     * 초기화 시 시크릿 키 Base64 인코딩
     */
    @PostConstruct
    protected void init() {
        SECRET_KEY = Base64.getEncoder().encodeToString(SECRET_KEY.getBytes());
    }

    /**
     * JWT 토큰 생성
     */
    public static String generateAccessToken(UserDetailsImpl userDetails) {
        Date now = new Date();

        return JWT.create()
                .withIssuer(ISSUER)
                .withClaim(CLAIM_USER_ID, userDetails.getUser().getUserId())
                .withClaim(CLAIM_USER_NAME, userDetails.getUsername())
                .withClaim(CLAIM_EXPIRED_DATE, new Date(now.getTime() + HOUR))
                .sign(getAlgorithm(SECRET_KEY));
    }
}
