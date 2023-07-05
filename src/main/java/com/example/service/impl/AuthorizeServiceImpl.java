package com.example.service.impl;

import com.example.entity.Account;
import com.example.mapper.UserMapper;
import com.example.service.AuthorizeService;
import jakarta.annotation.Resource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.mail.MailException;
import org.springframework.mail.MailSender;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Random;
import java.util.concurrent.TimeUnit;

@Service
public class AuthorizeServiceImpl implements AuthorizeService {
    @Value("${spring.mail.username}")
    String from;
    @Autowired
    StringRedisTemplate redisTemplate;
    @Resource
    UserMapper userMapper;
    @Resource
    MailSender mailSender;

    BCryptPasswordEncoder pwdEncoder = new BCryptPasswordEncoder();

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (username == null){
            throw new UsernameNotFoundException("用户名不能为空");
        }
        Account account = userMapper.findAccountByNameOrEmail(username);
        if (account == null){
            throw new UsernameNotFoundException("用户名或密码错误");
        }
        return User.withUsername(account.getUsername())
                .password(account.getPassword())
                .roles("user")
                .build();
    }

    /**
     * 1. 生成对应的验证码
     * 2. 发送验证码到指定邮箱
     * 3. 把邮箱和对应的验证码直接放到Redis里面（过期时间3分钟，如果此时重新要求发邮件，那么只要剩余时间低于2分钟，就可以再重新发送一次，重复此流程）
     * 4. 如果发送失败，把Redis里面的验证码删除
     * 5. 用户在注册时，再从Redis里面取出对应的键值对，然后看验证码是否一致
     */
    @Override
    public String sendValidateEmail(String email, String ip) {
        String key = "email:" +ip+":"+email;

        // 如果过期剩余时间大于120秒，则不允许再申请验证码
        if (Boolean.TRUE.equals(redisTemplate.hasKey(key))){
            Long expire = redisTemplate.getExpire(key, TimeUnit.SECONDS);
            if (expire > 120)
                return "请求频繁，请稍后再试";
        }
        // 如果邮箱已经被注册过，不能再发送
        if (userMapper.findAccountByNameOrEmail(email) != null)
            return "此邮箱已被其他人注册";
        // 否则可以再次申请
        Random random = new Random();
        int code = random.nextInt(899999) + 100000;
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(email);
        message.setSubject("你的验证邮件");
        message.setText("验证码是："+ code);
        try {
            mailSender.send(message);
            redisTemplate.opsForValue().set(key, String.valueOf(code), 3, TimeUnit.MINUTES);
            return null;
        }catch (MailException e){
            System.out.println("发送失败");
            e.printStackTrace();
        }
        return "邮件发送失败，请检查邮件地址是否有效";
    }

    @Override
    public String validateAdnRegister(String username, String password, String email, String code, String ip) {
        String key = "email:" +ip+":"+email;
        if (Boolean.TRUE.equals(redisTemplate.hasKey(key))){
            String value = redisTemplate.opsForValue().get(key);
            if (value == null) return "验证码失效，请重新请求";
            if (value.equals(code)){
                password = pwdEncoder.encode(password);
                if(userMapper.createAccount(username, password, email)>0)   return null;
                else return "内部错误，请联系管理员";
            }else{
                return "验证码错误";
            }
        }else{
            return "请先请求验证码";
        }
    }
}
