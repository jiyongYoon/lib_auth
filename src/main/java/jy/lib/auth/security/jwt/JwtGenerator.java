package jy.lib.auth.security.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import org.springframework.security.core.userdetails.UserDetails;

import javax.annotation.PostConstruct;
import java.util.Base64;
import java.util.Date;

public class JwtGenerator {
    public static String SECRET_KEY = "auth-test";
    private static final String ISSUER = "jiyong";
    private static final int SEC = 1000; //milli-sec
    private static final int MINUTE = 60 * SEC;
    private static final int HOUR = 60 * MINUTE;
    private static final int DAY = 24 * HOUR;
    private static final int JWT_TOKEN_VALID_SEC = 3 * DAY;
    private static final int JWT_TOKEN_VALID_MILLI_SEC = JWT_TOKEN_VALID_SEC * 1000;

    public static final String CLAIM_EXPIRED_DATE = "expired_date";
    public static final String CLAIM_USER_NAME = "user_name";

    public static final String TOKEN_PREFIX = "Bearer ";

    public static Algorithm getAlgorithm(String secretKey) {
        return Algorithm.HMAC256(secretKey);
    }

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
    public static String generateJwtToken(UserDetails userDetails) {
        Date now = new Date();

        return JWT.create()
                .withIssuer(ISSUER)
                .withClaim(CLAIM_USER_NAME, userDetails.getUsername())
                .withClaim(CLAIM_EXPIRED_DATE, new Date(now.getTime() + HOUR))
                .sign(getAlgorithm(SECRET_KEY));
    }

    /**
     * JWT 토큰 validate <br>
     * 1. 유효기간 검사 <br>
     * 2. 서명 검사 <br>
     * 3. 구조에 따라 public으로 오픈할 가능성 높음
     */
    public static DecodedJWT validateToken(String token) throws Exception {
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
