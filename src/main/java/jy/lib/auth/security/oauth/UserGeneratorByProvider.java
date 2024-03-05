package jy.lib.auth.security.oauth;

import com.fasterxml.jackson.databind.ObjectMapper;
import jy.lib.auth.entity.User;
import jy.lib.auth.security.oauth.info.NaverAttribute;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;

public class UserGeneratorByProvider {

    public static User generateUser(String providerIdentifier, OAuth2User oAuth2User, PasswordEncoder passwordEncoder, ObjectMapper objectMapper) {
        switch (providerIdentifier) {
            case "google":
                return User.builder()
                        .userEmail(oAuth2User.getAttribute("email"))
                        .userPassword(passwordEncoder.encode(oAuth2User.getAttribute("sub") + "_myApp"))
                        .userRole("ROLE_USER")
                        .provider(Provider.GOOGLE)
                        .build();
            case "kakao":
                return User.builder()
                        .userEmail(oAuth2User.getAttribute("id") + "")
                        .userPassword(passwordEncoder.encode(oAuth2User.getAttribute("id") + "_myApp"))
                        .userRole("ROLE_USER")
                        .provider(Provider.KAKAO)
                        .build();
            case "naver":
                NaverAttribute attribute =
                        objectMapper.convertValue(oAuth2User.getAttribute("response"), NaverAttribute.class);
                return User.builder()
                        .userEmail(attribute.getEmail())
                        .userPassword(passwordEncoder.encode(attribute.getId() + "_myApp"))
                        .userRole("ROLE_USER")
                        .provider(Provider.NAVER)
                        .build();
            default:
                return User.builder().build();
        }
    }
}
