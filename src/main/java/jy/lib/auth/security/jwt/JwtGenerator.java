package jy.lib.auth.security.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.security.core.userdetails.UserDetails;

import javax.annotation.PostConstruct;
import java.util.Base64;
import java.util.Date;

public class JwtGenerator {
    public static String SECRET_KEY = "auth-test";
    private static final String ISSUER = "jiyong";
    private static final int SEC = 1;
    private static final int MINUTE = 60 * SEC;
    private static final int HOUR = 60 * MINUTE;
    private static final int DAY = 24 * HOUR;
    private static final int JWT_TOKEN_VALID_SEC = 3 * DAY;
    private static final int JWT_TOKEN_VALID_MILLI_SEC = JWT_TOKEN_VALID_SEC * 1000;

    public static final String CLAIM_EXPIRED_DATE = "EXPIRED_DATE";
    public static final String CLAIM_USER_NAME = "USER_NAME";

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
                .withClaim(CLAIM_EXPIRED_DATE, new Date(now.getTime() + MINUTE))
                .sign(getAlgorithm(SECRET_KEY));
    }
}
