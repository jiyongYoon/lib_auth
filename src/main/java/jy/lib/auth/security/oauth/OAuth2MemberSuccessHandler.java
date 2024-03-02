package jy.lib.auth.security.oauth;

import java.io.IOException;
import java.net.URI;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import jy.lib.auth.security.UserDetailsImpl;
import jy.lib.auth.security.jwt.RefreshTokenStorage;
import jy.lib.auth.security.jwt.dto.GenerateJwtRequest;
import jy.lib.auth.security.jwt.util.JwtGenerator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

@Slf4j
@RequiredArgsConstructor
public class OAuth2MemberSuccessHandler implements AuthenticationSuccessHandler {

    private final RefreshTokenStorage refreshTokenStorage;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
        Authentication authentication) throws IOException {
        log.info("oauth2 user login success!! username={}", authentication);
        UserDetailsImpl authenticateUserDetails = (UserDetailsImpl) authentication.getPrincipal();

        String accessToken = JwtGenerator.generateAccessToken(GenerateJwtRequest.builder()
            .userId(authenticateUserDetails.getUser().getUserId())
            .username(authenticateUserDetails.getUsername())
            .build());
        String refreshToken = JwtGenerator.generateRefreshToken();

        refreshTokenStorage.saveAccessAndRefreshToken(accessToken, refreshToken);

        response.sendRedirect(createURI(
            accessToken,
            refreshToken,
            authenticateUserDetails.getUser().getUserId(),
            authenticateUserDetails.getUser().getUserEmail()).toString());
    }

    private URI createURI(String accessToken, String refreshToken, Long userId, String username) {
        MultiValueMap<String, String> queryParams = new LinkedMultiValueMap<>();
        queryParams.add("user_id", String.valueOf(userId));
        queryParams.add("user_name", username);
        queryParams.add("access_token", accessToken);
        queryParams.add("refresh_token", refreshToken);

        return UriComponentsBuilder
            .newInstance()
            .scheme("http")
//            .host("localhost:8080")
            .path("/api/oauth-jwt")
            .queryParams(queryParams)
            .build()
            .toUri();
    }
}
