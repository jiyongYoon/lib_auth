package jy.lib.auth.security.config;

import jy.lib.auth.security.PrincipalOauth2UserServiceImpl;
import jy.lib.auth.security.filter.CustomFilter;
import jy.lib.auth.security.jwt.RefreshTokenStorage;
import jy.lib.auth.security.oauth.OAuth2MemberSuccessHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurityConfig {

    private final RefreshTokenStorage refreshTokenStorage;

    private final PrincipalOauth2UserServiceImpl principalOauth2UserServiceImpl;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable();

        http
//                jwt 사용시 필요없음
//                .httpBasic()
//            .and()
                .authorizeRequests()
                    .antMatchers("/api/signup").permitAll()
                    .antMatchers("/api/login").permitAll()
                    .antMatchers("/api/token").permitAll()
                    .antMatchers("/oauth/login").permitAll() // oauth login 호출 버튼이 있는 페이지
                    .antMatchers("/api/oauth-jwt").permitAll() // oauth login 후 토큰정보를 가진 redirect url 을 받아서 헤더에 추가하는 페이지
                    .antMatchers("/api/context").permitAll() // 현재 context에 있는 정보
                    .anyRequest().authenticated()
//            .and()
//                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER)
            .and()
                .formLogin().disable()
                .httpBasic().disable()
                .apply(new CustomFilter(refreshTokenStorage))
            .and()
                .oauth2Login()
                .successHandler(new OAuth2MemberSuccessHandler(refreshTokenStorage))
                .userInfoEndpoint()
                .userService(principalOauth2UserServiceImpl)
                ;

        return http.build();
    }

    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

}
