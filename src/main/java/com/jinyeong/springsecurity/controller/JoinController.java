package com.jinyeong.springsecurity.controller;

import com.jinyeong.springsecurity.domain.User;
import com.jinyeong.springsecurity.service.JoinService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class JoinController {
    private final JoinService joinService;

    public JoinController(JoinService joinService) {
        this.joinService = joinService;
    }

    @GetMapping("/join")
    public String joinPage() {
        return "join";
    }


    @PostMapping("/joinProc")
    public String joinProcess(User user) {
        System.out.println(user.getUsername());
        joinService.joinProcess(user);

        return "redirect:/login";
    }
}
