package jy.lib.auth.security;

import jy.lib.auth.entity.User;
import jy.lib.auth.repository.UserRepository;
import jy.lib.auth.security.oauth.UserGeneratorByProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class PrincipalOauth2UserServiceImpl extends DefaultOAuth2UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        System.out.println("oAuth2User = " + oAuth2User.getAttributes());

        Optional<User> optionalUser = userRepository.findByEmail(oAuth2User.getAttribute("email"));
        User user;
        if (optionalUser.isEmpty()) {
            String providerIdentifier = userRequest.getClientRegistration().getRegistrationId();
            user = UserGeneratorByProvider.generateUser(providerIdentifier, oAuth2User, passwordEncoder);
            userRepository.save(user);
        } else {
            user = optionalUser.get();
        }

        return new UserDetailsImpl(user, oAuth2User.getAttributes());
    }
}
