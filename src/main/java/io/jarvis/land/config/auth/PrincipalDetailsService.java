package io.jarvis.land.config.auth;

import io.jarvis.land.entity.User;
import io.jarvis.land.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// 시큐리티 설정에서 /login 요청이 오면 자동으로 UserDetailsService 타입으로 IoC되어 있는 loadUserByUsername 함수가 실행
@Service
@Slf4j
public class PrincipalDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    // 시큐리티 session(내부 authentication(내부 userdetails))
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info("username:"+username);
        User userEntity = userRepository.findByUsername(username);
        if(userEntity != null) {
            return new PrincipalDetails(userEntity);
        }
        return null;
    }
}
