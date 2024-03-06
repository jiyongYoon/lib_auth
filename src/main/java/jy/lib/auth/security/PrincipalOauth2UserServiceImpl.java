package jy.lib.auth.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jy.lib.auth.entity.User;
import jy.lib.auth.repository.UserRepository;
import jy.lib.auth.security.oauth.OAuth2Provider;
import jy.lib.auth.security.oauth.user_info.OAuthUserInfo;
import jy.lib.auth.security.oauth.user_info.OAuthUserInfoMaker;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

@Service
public class PrincipalOauth2UserServiceImpl extends DefaultOAuth2UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final ObjectMapper objectMapper;

    private final Map<OAuth2Provider, OAuthUserInfoMaker> oAuthUserInfoMakerMap = new HashMap<>();

    public PrincipalOauth2UserServiceImpl(Set<OAuthUserInfoMaker> oAuthUserInfoMakerSet,
                                          UserRepository userRepository,
                                          PasswordEncoder passwordEncoder,
                                          ObjectMapper objectMapper) {
        oAuthUserInfoMakerSet.forEach(
                oAuthUserInfoMaker -> oAuthUserInfoMakerMap.put(
                        oAuthUserInfoMaker.getOAuto2Provider(),
                        oAuthUserInfoMaker
                )
        );
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.objectMapper = objectMapper;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        System.out.println("oAuth2User = " + oAuth2User.getAttributes());

        Optional<User> optionalUser = userRepository.findByEmail(oAuth2User.getAttribute("email"));
        User user;
        if (optionalUser.isEmpty()) {
            user = generateUserByProvider(userRequest, oAuth2User);
            userRepository.save(user);
        } else {
            user = optionalUser.get();
        }

        return new UserDetailsImpl(user, oAuth2User.getAttributes());
    }

    private User generateUserByProvider(OAuth2UserRequest userRequest, OAuth2User oAuth2User) {
        String providerIdentifier = userRequest.getClientRegistration().getRegistrationId();
        OAuthUserInfoMaker oAuthUserInfoMaker =
                oAuthUserInfoMakerMap.get(OAuth2Provider.getProvider(providerIdentifier));
        OAuthUserInfo oAuthUserInfo = oAuthUserInfoMaker.makeUserInfo(oAuth2User);
        return User.builder()
                .userEmail(oAuthUserInfo.getUserEmail())
                .userPassword(passwordEncoder.encode(oAuthUserInfo.getUserPasswordNotEncoded() + "_myApp"))
                .userRole(oAuthUserInfo.getUserRole())
                .oAuth2Provider(oAuthUserInfo.getOAuth2Provider())
                .build();
    }
}
