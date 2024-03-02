package jy.lib.auth.security;

import java.util.Map;
import jy.lib.auth.entity.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import org.springframework.security.oauth2.core.user.OAuth2User;

/**
 * @UserDetails 일반 회원가입 및 로그인 시 만들어지는 객체
 * @OAuth2User OAuth 회원가입 및 로그인 시 만들어지는 객체
 * @UserDetailsImpl 두 객체를 모두 구현하여 App 내에서는 해당 객체를 사용
 */
public class UserDetailsImpl implements UserDetails, OAuth2User {

    private User user;
    private Map<String, Object> attributes;

    // 일반 로그인
    public UserDetailsImpl(User user) {
        this.user = user;
    }

    // OAuth 로그인
    public UserDetailsImpl(User user, Map<String, Object> attributes) {
        this.user = user;
        this.attributes = attributes;
    }

    public User getUser() {
        return this.user;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> grantedAuthorityCollection = new ArrayList<>();
        grantedAuthorityCollection.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getUserRole();
            }
        });
        return grantedAuthorityCollection;
    }

    @Override
    public String getPassword() {
        return this.user.getUserPassword();
    }

    @Override
    public String getUsername() {
        return this.user.getUserEmail();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public String getName() {
        return String.valueOf(attributes.get("name"));
    }

    @Override
    public String toString() {
        return "UserDetailsImpl{" +
            "user=" + user.getUserEmail() +
            ", attributes=" + attributes +
            '}';
    }
}
