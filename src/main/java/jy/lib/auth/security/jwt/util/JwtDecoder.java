package jy.lib.auth.security.jwt.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

import java.util.Date;

import static jy.lib.auth.security.jwt.JwtProperties.*;


public class JwtDecoder {

    /**
     * JWT 토큰의 유저명 가져오기
     */
    public static String getUsernameByJwtToken(String token) throws Exception {
        DecodedJWT decodedToken = validateToken(token);
        return decodedToken.getClaim(CLAIM_USER_NAME).asString();
    }

    /**
     * JWT 토큰 validate <br>
     * 1. 유효기간 검사 <br>
     * 2. 서명 검사 <br>
     * 3. 구조에 따라 public으로 오픈할 가능성 높음
     */
    public static DecodedJWT validateToken(String token) {
        Date now = new Date();
        Date tokenExpiredDate = JWT.decode(token).getClaim(CLAIM_EXPIRED_DATE).asDate();
        if (tokenExpiredDate.before(now)) {
            throw new RuntimeException("유효기간이 지난 토큰입니다. 유효기간: " + tokenExpiredDate);
        }

        JWTVerifier verifier = JWT
                .require(getAlgorithm(SECRET_KEY))
                .build();

        return verifier.verify(token);
    }
}
