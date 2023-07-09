package com.example.service;

import org.springframework.security.core.userdetails.UserDetailsService;

public interface AuthorizeService extends UserDetailsService {
    String sendValidateEmail(String email, String sessionId, boolean hasAccount);
    String validateAdnRegister(String username, String password, String email, String code, String sessionId);
    String validateOnly(String email, String code, String sessionId);

    String resetPassword(String email, String code, String password, String sessionId);
}
