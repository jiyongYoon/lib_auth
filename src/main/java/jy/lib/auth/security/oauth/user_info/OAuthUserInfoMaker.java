package jy.lib.auth.security.oauth.user_info;

import jy.lib.auth.security.oauth.OAuth2Provider;
import org.springframework.security.oauth2.core.user.OAuth2User;

public interface OAuthUserInfoMaker {

    OAuthUserInfo makeUserInfo(OAuth2User oAuth2User);
    OAuth2Provider getOAuto2Provider();
}
