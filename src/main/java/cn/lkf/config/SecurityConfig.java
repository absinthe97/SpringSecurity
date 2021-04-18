package cn.lkf.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    //授权的规则
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //定义访问规则
        //首页所有人可以访问,功能页只有对应有权限的人才能访问
        http.authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/adminLogin").hasAnyRole("admin")
                .antMatchers("/userLogin").hasAnyRole("user");

        //没有权限默认会到登录页面
        http.formLogin();
    }

    //认证的规则

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //这些数据正常应该从数据库中读取
        auth.inMemoryAuthentication()
                .passwordEncoder(new BCryptPasswordEncoder())
                .withUser("lkf").password(new BCryptPasswordEncoder().encode("123456"))
                .roles("admin","user");
    }
}
