package jy.lib.auth.security.jwt;

import com.auth0.jwt.algorithms.Algorithm;

public class JwtProperties {

    public static String SECRET_KEY = "auth-test";
    public static final String ISSUER = "jiyong";
    public static final int SEC = 1000; //milli-sec
    public static final int MINUTE = 60 * SEC;
    public static final int HOUR = 60 * MINUTE;
    public static final int DAY = 24 * HOUR;
    public static final int JWT_TOKEN_VALID_SEC = 3 * DAY;

    public static final String CLAIM_EXPIRED_DATE = "expired_date";
    public static final String CLAIM_USER_NAME = "user_name";
    public static final String CLAIM_USER_ID = "user_id";

    public static final String TOKEN_PREFIX = "Bearer ";

    public static Algorithm getAlgorithm(String secretKey) {
        return Algorithm.HMAC256(secretKey);
    }
}
