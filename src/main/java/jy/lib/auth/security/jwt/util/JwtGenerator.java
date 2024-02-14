package jy.lib.auth.security.jwt.util;

import com.auth0.jwt.JWT;
import jy.lib.auth.security.jwt.dto.GenerateJwtRequest;

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
     * JWT Access Token 생성
     */
    public static String generateAccessToken(GenerateJwtRequest generateJwtRequest) {
        Date now = new Date();

        return JWT.create()
                .withIssuer(ISSUER)
                .withClaim(CLAIM_USER_ID, generateJwtRequest.getUserId())
                .withClaim(CLAIM_USER_NAME, generateJwtRequest.getUsername())
                .withClaim(CLAIM_EXPIRED_DATE, new Date(now.getTime() + MINUTE / 2))
                .sign(getAlgorithm(SECRET_KEY));
    }

    /**
     * JWT Refresh Token 생성
     */
    public static String generateRefreshToken() {
        Date now = new Date();

        return JWT.create()
                .withIssuer(ISSUER)
                .withIssuedAt(now)
                .sign(getAlgorithm(SECRET_KEY));
    }

}
