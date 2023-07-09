package com.example.controller;

import com.example.entity.RestBean;
import com.example.service.AuthorizeService;
import com.example.utils.IpUtil;
import jakarta.annotation.Resource;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.constraints.Pattern;
import org.apache.catalina.connector.Request;
import org.hibernate.validator.constraints.Length;
import org.springframework.stereotype.Service;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@Validated
@RestController
@RequestMapping("/api/auth")
public class AuthorizeController {

    @Resource
    AuthorizeService authorizeSvr;

    private final String EMAIL_REGEX = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+.[A-Za-z]{2,}$";
    private final String USERNAME_REGEX = "^[a-zA-Z0-9\\u4e00-\\u9fa5]+$";
    @PostMapping("/valid-register-email")
    public RestBean<String> validateRegisterEmail(@Pattern(regexp = EMAIL_REGEX)@RequestParam("email") String email,
                                          HttpServletRequest request,
                                                  HttpSession session){
        System.out.println("sessionId="+session.getId());
        String result = authorizeSvr.sendValidateEmail(email, session.getId(), false);
        if (result == null){
            return RestBean.success("邮件已发送，请注意查收");
        }else{
            return RestBean.failure(400,result);
        }
    }

    @PostMapping("/valid-reset-email")
    public RestBean<String> validateRestEmail(@Pattern(regexp = EMAIL_REGEX)@RequestParam("email") String email,
                                          HttpServletRequest request,
                                              HttpSession session){
        System.out.println("sessionId="+session.getId());
        String result = authorizeSvr.sendValidateEmail(email, session.getId(), true);
        if (result == null){
            return RestBean.success("邮件已发送，请注意查收");
        }else{
            return RestBean.failure(400,result);
        }
    }

    @PostMapping("/register")
    public RestBean<String> registerUser(@Pattern(regexp = USERNAME_REGEX) @Length(min = 2, max = 30) @RequestParam("username") String username,
                                         @Length(min = 6, max = 16) @RequestParam("password") String password,
                                         @Pattern(regexp = EMAIL_REGEX) @RequestParam("email") String email,
                                         @Length(min = 6, max = 6) @RequestParam("code") String code,
                                         HttpServletRequest request,
                                         HttpSession session){
        System.out.println("sessionId="+session.getId());
        String result = authorizeSvr.validateAdnRegister(username, password, email, code, session.getId());
        if (result == null){
            return RestBean.success("注册成功");
        }else{
            return RestBean.failure(400, result);
        }
    }

    @PostMapping("/reset-password")
    public RestBean<String> resetPassword(@Pattern(regexp = EMAIL_REGEX) @RequestParam("email") String email,
                                      @Length(min = 6, max = 16) @RequestParam("password") String password,
                                      @Length(min = 6, max = 6) @RequestParam("code") String code,
                                      HttpServletRequest request,
                                          HttpSession session){
        System.out.println("sessionId="+session.getId());
        String result = authorizeSvr.resetPassword(email, code, password, session.getId());
        if (result == null){
            return RestBean.success("密码修改成功");
        }else{
            return RestBean.failure(400, result);
        }
    }
}
