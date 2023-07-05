package com.example.service;

import org.springframework.security.core.userdetails.UserDetailsService;

public interface AuthorizeService extends UserDetailsService {
    String sendValidateEmail(String email, String ip);
    String validateAdnRegister(String username, String password, String email, String code, String ip);
}
