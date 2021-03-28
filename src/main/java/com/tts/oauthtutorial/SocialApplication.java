package com.tts.oauthtutorial;

import java.util.Collections;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;



@SpringBootApplication
@RestController
public class SocialApplication extends WebSecurityConfigurerAdapter
{

    @GetMapping("/user")
    public Map<String, Object> user(@AuthenticationPrincipal OAuth2User principal)
    {
        return Collections.singletonMap("name", principal.getAttribute("name"));
    }
    
 
    public static void main(String[] args)
    {
        SpringApplication.run(SocialApplication.class, args);
    }

    // What we were told to copy/paste in the tutorial...
    // @GetMapping("/error")
    // public String error() {
    // String message = (String) request.getSession().getAttribute("error.message");
    // request.getSession().removeAttribute("error.message");
    // return message;
    // }

    // ...vs what was in the source code
    @GetMapping("/error")
    @ResponseBody
    public String error(HttpServletRequest request)
    {
        String message = (String) request.getSession().getAttribute("error.message");
        request.getSession().removeAttribute("error.message");
        return message;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception
    {
        SimpleUrlAuthenticationFailureHandler handler = new SimpleUrlAuthenticationFailureHandler("/");

        // @formatter:off
        http.authorizeRequests(a -> a.antMatchers("/", "/error", "/webjars/**").permitAll().anyRequest().authenticated())
                .exceptionHandling(e -> e.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))).logout(l -> l.logoutSuccessUrl("/").permitAll())
                .csrf(c -> c.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())).oauth2Login(o -> o.failureHandler((request, response, exception) ->
                { request.getSession().setAttribute("error.message", exception.getMessage()); handler.onAuthenticationFailure(request, response, exception); }));
    }
    // @formatter:on
    



}


