package com.jinyeong.springsecurity.service;

import com.jinyeong.springsecurity.domain.CustomUserDetails;
import com.jinyeong.springsecurity.entity.UserEntity;
import com.jinyeong.springsecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    /**
     * Spring Security 는 기본적으로 UserDetailsService 인터페이스의 구현체를 찾아 사용한다.
     * 사용자가 로그인 폼을 제출하면, Spring Security 의 UsernamePasswordAuthenticationFilter 가 요청을 가로챈다.
     * AuthenticationManager 는 UserDetailsService 를 사용하여 사용자 정보를 로드한다.
     * 내가 구현한 CustomUserDetailsService 가 UserDetailsService 를 구현하고 있어서 oadUserByUsername 메소드가 호출되어 사용자 정보를 로드한다.
     * 로드된 사용자 정보를 바탕으로 비밀번호 검증 등의 인증 과정이 진행된다.
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity userData = userRepository.findByUsername(username);

        if (userData != null) {
            return new CustomUserDetails(userData);
        }

        return null;
    }
}
