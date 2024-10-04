package com.jinyeong.springsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    /**
     * Spring Security 에서 권한하는 암호화 방식 (단방향 - 해시)
     */
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 계층 권한: Role Hierarchy - 권한에 우선순위를 부여하여 계층을 이룰수 있다.
     * 만약 USER 권한을 가진 클라이언트가 /admin 페이지에 접근하면 접속이 차단된다.
     */
    @Bean
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();
        hierarchy.setHierarchy("ROLE_ADMIN > ROLE_MANAGER > ROLE_USER");
        return hierarchy;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        /**
         * 구현한 CustomUserDetailsService 의 loadUserByUsername 통해 User 정보를 로그하여 role 체크를 한다.
         * User 의 role 에 "ROLE_ADMIN"이 없으면 로그인 후에 /admin 에 대한 page 접근이 제한된다.
         *
         * 로그인에 성공한 사용자의 정보는 Spring Security 의 SecurityContext 에 저장된다.
         */
        http.authorizeHttpRequests((auth) -> auth
                .requestMatchers("/", "/login", "/loginProc", "/join", "/joinProc").permitAll()
                .requestMatchers("/admin").hasRole("ADMIN")
                .requestMatchers("/manager").hasRole("MANAGER")
                .requestMatchers("/manager").hasRole("USER")
                .requestMatchers("/my/**").hasAnyRole("ADMIN", "USER")
                .anyRequest().authenticated());

        http.formLogin((auth) -> auth.loginPage("/login")
                        .loginProcessingUrl("/loginProc")
                        .permitAll());

        /**
         * CSRF(Cross-Site Request Forgery)
         * - 요청을 위조하여 사용자가 원하지 않아도 서버측으로 특정 요청을 강제로 보내는 방식
         * - Spring Security는 CsrfFilter를 통해 POST, PUT, DELETE 요청에 대해서 토큰 검증을 진행
         * - 설정을 따로 진행하지 않으면 자동으로 enable 설정이 진행
         * - CSRF Token을 관리하는 시스템을 별도로 구축 해야한다.
         * - 앱에서 사용하는 API 서버의 경우 보통 세션을 STATELESS 하게 관리하기 때문에 스프링 시큐리티 CSRF를 enable로 설정 할 필요가 없다.
         */
        http.csrf(AbstractHttpConfigurer::disable);

        /**
         * maximumSession(정수) : 하나의 아이디에 대한 다중 로그인 허용 개수
         * maxSessionPreventsLogin(boolean) : 다중 로그인 개수를 초과하였을 경우 처리 방법
         * - true : 초과시 새로운 로그인 차단
         * - false : 초과시 기존 세션 하나 삭제
         */
        http.sessionManagement((auth) -> auth
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(true));

        /**
         * [세션고정보호]
         * Hacker가 User의 SessionId를 탈취하여 동일한 세션 쿠키로 접속해 해당 계정의 권한을 대행하는 을 방지
         * - changeSessionId(): 주로사용하는 방식, 로그인 시 동일한 세션에 대한 SessionId 변경
         */
        http.sessionManagement((auth) -> auth.sessionFixation().changeSessionId());

        return http.build();
    }
}