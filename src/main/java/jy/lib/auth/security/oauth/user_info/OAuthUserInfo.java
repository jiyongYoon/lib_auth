package jy.lib.auth.security.oauth.user_info;

import jy.lib.auth.security.oauth.OAuth2Provider;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class OAuthUserInfo {
    private String userEmail;
    private String userPasswordNotEncoded;
    private String userRole;
    private OAuth2Provider oAuth2Provider;
}
