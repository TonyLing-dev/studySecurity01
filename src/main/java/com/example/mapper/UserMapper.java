package com.example.mapper;

import com.example.entity.Account;
import com.example.entity.AccountUser;
import org.apache.ibatis.annotations.*;

@Mapper
public interface UserMapper {

    @Select("select * from db_account where username = #{text} or email = #{text}")
    Account findAccountByNameOrEmail(String text);
    @Select("select * from db_account where username=#{text} or email=#{text}")
    AccountUser findAccountUserByNameOrEmail(String text);

    @Insert("insert into db_account(username, password, email ) values (#{username}, #{password}, #{email}) ")
    int createAccount(@Param("username") String username,@Param("password") String password,@Param("email") String email);
    @Update("update db_account set password = #{password} where email = #{email}")
    int resetPasswordByEmail(@Param("password") String password, @Param("email") String email);
}
