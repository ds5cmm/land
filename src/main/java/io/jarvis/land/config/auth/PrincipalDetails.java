package io.jarvis.land.config.auth;

// 시큐리티가 login주소 요청시 낚아채서 로그인 진행
// 로그인을 진행완료되면 시큐리티 session을 만들어줌.

import io.jarvis.land.entity.User;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

@Data
public class PrincipalDetails implements UserDetails, OAuth2User {

    private User user;
    private Map<String, Object> attributes;

    public PrincipalDetails(User user) {
        this.user = user;
    }

    public PrincipalDetails(User user, Map<String, Object> attributes) {
        this.user = user;
        this.attributes = attributes;
    }



    // 해당 유저의 권한을 리턴
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collect = new ArrayList<>();
        collect.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });
        return collect;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    // 유효기간
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    // 잠긴여부
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    // 오래사용했는지여부
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    // 사용여부
    @Override
    public boolean isEnabled() {
        // 우리 사이트에서 1년동안 회원이 로그인을 안하면 휴면계정 설정
        // 현재시간 - 로그인시간 => 1년이상인경우 false
        return true;
    }

    @Override
    public Map<String, Object> getAttributes() {

        return attributes;
    }

    @Override
    public String getName() {
        return attributes.get("sub").toString();
    }
}
