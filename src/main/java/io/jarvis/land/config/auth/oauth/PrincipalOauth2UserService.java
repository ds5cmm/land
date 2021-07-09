package io.jarvis.land.config.auth.oauth;

import io.jarvis.land.config.auth.PrincipalDetails;
import io.jarvis.land.config.auth.oauth.provider.GoogleUserInfo;
import io.jarvis.land.config.auth.oauth.provider.NaverUserInfo;
import io.jarvis.land.config.auth.oauth.provider.OAuth2UserInfo;
import io.jarvis.land.entity.User;
import io.jarvis.land.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

import java.util.Map;

@RequiredArgsConstructor
@Service
@Slf4j
public class PrincipalOauth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private UserRepository userRepository;

    // oauth2 처리함수
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        Assert.notNull(userRequest, "userRequest cannot be null");
        OAuth2UserService delegate = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = delegate.loadUser(userRequest);

        log.info("loadUser:"+userRequest.getClientRegistration());
        OAuth2UserInfo oAuth2UserInfo = null;
        if(userRequest.getClientRegistration().getRegistrationId().equals("google")) {
            log.info("구글 로그인 요청");
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        } else if(userRequest.getClientRegistration().getRegistrationId().equals("naver")) {
            log.info("네이버 로그인 요청");
            oAuth2UserInfo = new NaverUserInfo((Map)oAuth2User.getAttributes().get("response"));
        } else {
            log.info("우리는 구글, 네이버 접속만 지원합니다.");
        }
        String provider = oAuth2UserInfo.getProvider();
        String providerId = oAuth2UserInfo.getProviderId();
        String username = provider+"_"+providerId;
        String password = bCryptPasswordEncoder.encode("oauth2password");
        String email = oAuth2UserInfo.getEmail();
        String role = "ROLE_USER";

        // 존재여부 확인
        User userEntity = userRepository.findByUsername(username);
        if(userEntity == null) {
            log.info("로그인 하신적이 없습니다. 자동 회원가입 진행됩니다.");
            // 회원가입 진행
            userEntity = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(userEntity);
        } else {
            log.info("구글로 이미 회원가입되었습니다.");
        }

        return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
    }
}
