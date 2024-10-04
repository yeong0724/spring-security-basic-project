package com.jinyeong.springsecurity.service;

import com.jinyeong.springsecurity.domain.User;
import com.jinyeong.springsecurity.entity.UserEntity;
import com.jinyeong.springsecurity.repository.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class JoinService {
    private final UserRepository userRepository;

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public JoinService(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    public void joinProcess(User user) {
        //db에 이미 동일한 username 을 가진 회원이 존재하는지?
        boolean isUser = userRepository.existsByUsername(user.getUsername());
        if (isUser) {
            System.out.println("이미 존재 하는 회원 : " + user.getUsername());
            return;
        }

        UserEntity data = new UserEntity();

        data.setUsername(user.getUsername());
        data.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        data.setRole("ROLE_USER");

        userRepository.save(data);
    }
}
