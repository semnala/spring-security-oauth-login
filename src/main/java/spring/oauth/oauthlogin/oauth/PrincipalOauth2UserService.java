package spring.oauth.oauthlogin.oauth;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {
    
    // 구글로 부터 받은 userRequest 데이터에 대한 후처리되는 함수
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        log.info("user getAccessToken: {}", userRequest.getAccessToken().getTokenValue());
        log.info("user getClientRegistration: {}", userRequest.getClientRegistration());
        log.info("user getAdditionalParameters: {}", userRequest.getAdditionalParameters());
        // 구글 로그인 버튼 클릭 -> 구글로그인창 -> 로그인완료 -> code 리턴(OAuth-client라이브러리) -> Access Token 요청
        // userRequest 정보 -> loadUser함수 호출 -> 구글로부터 회원 프로필 받아온다
        log.info("user getAttributes: {}", super.loadUser(userRequest).getAttributes());
        return super.loadUser(userRequest);
    }
}
