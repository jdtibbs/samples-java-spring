package com.okta.spring.example;

import com.okta.spring.boot.oauth.Okta;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Date;
import java.util.Map;
import org.springframework.web.bind.annotation.ResponseBody;

@SpringBootApplication
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class ResourceServerExampleApplication {

    public static void main(String[] args) {
        SpringApplication.run(ResourceServerExampleApplication.class, args);
    }

    @Configuration
    static class OktaOAuth2WebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.authorizeRequests()
                .anyRequest()
                .authenticated()
                .and()
                .oauth2ResourceServer().jwt();
//                .oauth2ResourceServer().opaqueToken();

            // process CORS annotations
            http.cors();

            // force a non-empty response body for 401's to make the response more browser friendly
            Okta.configureResourceServer401ResponseBody(http);
        }
    }

    @RestController
    @CrossOrigin(origins = "http://localhost:3000")
    public class MessageOfTheDayController {

        @GetMapping("/api/userProfile")
//        @PreAuthorize("hasAuthority('Everyone')")
        @PreAuthorize("hasAuthority('SCOPE_openid')")
//        @PreAuthorize("hasRole('APP_PMHorizon_IT')")
        public <A extends AbstractOAuth2TokenAuthenticationToken<AbstractOAuth2Token>> Map<String, Object> getUserDetails(A authentication) {
            System.out.println("/api/userProfile");
            return authentication.getTokenAttributes();
        }
               
                
        @GetMapping("/api/admin")
        @ResponseBody
//        @PreAuthorize("hasAuthority('SCOPE_openid')")
        @PreAuthorize("hasAuthority('Admin')")
//      @PreAuthorize("hasRole('ADMIN')") // to use Spring hasRoles, add Okta group with name ROLE_ADMIN
        public String admin() {
            System.out.println("/api/admin");
            return "Hello, Admin!";
        }

        @GetMapping("/api/multiGroup")
        @ResponseBody
//        @PreAuthorize("hasAuthority('SCOPE_openid')")
        @PreAuthorize("hasAnyAuthority('Admin','Team_UW')")
        public String multiGroup() {
            System.out.println("/api/multiGroup");
            return "Hello, Admin & Underwriting!";
        }
        
        @GetMapping("/api/everyone")
        @ResponseBody
        @PreAuthorize("hasAuthority('SCOPE_openid')")
        // @PreAuthorize("hasAuthority('SCOPE_email')")        
        // @PreAuthorize("hasAuthority('SCOPE_profile')")
        public String everyone() {
            System.out.println("/api/everyone");
            return "Hello, Everyone!";
        }

    }

    class Message {

        public Date date = new Date();
        public String text;

        Message(String text) {
            this.text = text;
        }
    }
}
