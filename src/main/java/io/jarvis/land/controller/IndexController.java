package io.jarvis.land.controller;

import io.jarvis.land.config.auth.PrincipalDetails;
import io.jarvis.land.entity.User;
import io.jarvis.land.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@Slf4j
public class IndexController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping({"", "/"})
    public String index() {
        return "index";
    }

    @GetMapping("/user")
    public @ResponseBody String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        log.info("principalDetails:"+principalDetails.getUser());
        return "user";
    }

    @GetMapping("/admin")
    public @ResponseBody String admin() {
        return "admin";
    }

    @GetMapping("/manager")
    public @ResponseBody String manager() {
        return "manager";
    }

    // SecurityConfig 파일생성후 작동안함
    @GetMapping("/loginForm")
    public String loginForm() {
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm() {
        return "joinForm";
    }

    @PostMapping("/join")
    public String join(User user) {
        String rawPassword = user.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);
        user.setPassword(encPassword);
        User result = userRepository.save(user);
        log.info(result.toString());
        return "redirect:/loginForm";
    }

    @Secured("ROLE_ADMIN")
    @GetMapping("/info")
    public @ResponseBody String info() {
        return "개인정보";
    }

    @PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROL_MANAGER')")
    @GetMapping("/data")
    public @ResponseBody String data() {
        return "데이터";
    }

    @GetMapping("/test/login")
    public @ResponseBody String testLogin(Authentication authentication,
                                          @AuthenticationPrincipal PrincipalDetails userDetails) {
        PrincipalDetails principalDetails = (PrincipalDetails)authentication.getPrincipal();
        log.info("authentication:"+principalDetails.getUsername());
        log.info("userDetail:"+userDetails.getUsername());
        return "세션 정보 확인";
    }

    @GetMapping("/test/oauth/login")
    public @ResponseBody String testOAuthLogin(Authentication authentication,
                                               @AuthenticationPrincipal OAuth2User oauth2) {
        OAuth2User oAuth2User = (OAuth2User)authentication.getPrincipal();
        log.info("authentication:"+oAuth2User.getAttribute("name"));
        log.info("oauth2:"+oauth2.getAttribute("name"));
        return "OAuth 세션 정보 확인";
    }
}
