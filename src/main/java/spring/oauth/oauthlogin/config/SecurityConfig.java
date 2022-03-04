package spring.oauth.oauthlogin.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import spring.oauth.oauthlogin.oauth.PrincipalOauth2UserService;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private PrincipalOauth2UserService principalOauth2UserService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();

        http
                .authorizeRequests()
                .antMatchers("/user/**").authenticated()
                .anyRequest().permitAll()
                .and()
                .formLogin()
                .loginPage("/loginForm")
                .loginProcessingUrl("/login")
                .defaultSuccessUrl("/")
                //.and()
        ;

        http
                /**
                 * 구글 로그인 완료된 뒤에 후처리가 필요
                 * 1. 코드받기(인증)
                 * 2. 엑세스토큰(권한)
                 * 3. 사용자프로필 정보 가져오기
                 * 4-1. 그 정보를 토대로 회원가입 자동 진행시키기도 함.
                 * 4-2. 추가적인 정보가 필요하다면 해당 정보를 입력하는 회원가입 폼을 나타냄.
                 *
                 */
                .oauth2Login()
                .loginPage("/loginForm")
                .userInfoEndpoint()
                .userService(principalOauth2UserService)
                ;

    }
}
