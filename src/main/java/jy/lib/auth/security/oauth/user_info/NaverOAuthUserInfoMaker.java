package jy.lib.auth.security.oauth.user_info;

import jy.lib.auth.security.oauth.OAuth2Provider;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class NaverOAuthUserInfoMaker implements OAuthUserInfoMaker {

    @Override
    public OAuthUserInfo makeUserInfo(OAuth2User oAuth2User) {
        Map<String, String> response = oAuth2User.getAttribute("response");
        OAuthUserInfo oAuthUserInfo = new OAuthUserInfo();
        oAuthUserInfo.setUserEmail(response.get("email"));
        oAuthUserInfo.setUserPasswordNotEncoded(response.get("id"));
        oAuthUserInfo.setUserRole("ROLE_USER");
        oAuthUserInfo.setOAuth2Provider(OAuth2Provider.NAVER);
        return oAuthUserInfo;
    }

    @Override
    public OAuth2Provider getOAuto2Provider() {
        return OAuth2Provider.NAVER;
    }
}
