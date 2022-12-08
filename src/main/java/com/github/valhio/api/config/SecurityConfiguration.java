package com.github.valhio.api.config;

import com.github.valhio.api.filter.JWTAccessDeniedHandler;
import com.github.valhio.api.filter.JWTAuthenticationEntryPoint;
import com.github.valhio.api.filter.JWTAuthorizationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

import static com.github.valhio.api.constant.SecurityConstant.PUBLIC_URLS;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

/*
*   This class is responsible for configuring the security of the application.
* */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfiguration {
    private final JWTAuthorizationFilter jwtAuthorizationFilter;
    private final JWTAccessDeniedHandler jwtAccessDeniedHandler;
    private final JWTAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final UserDetailsService userDetailsService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    public SecurityConfiguration(JWTAuthorizationFilter jwtAuthorizationFilter,
                                 JWTAccessDeniedHandler jwtAccessDeniedHandler,
                                 JWTAuthenticationEntryPoint jwtAuthenticationEntryPoint,
                                 @Qualifier("userDetailsService") UserDetailsService userDetailsService,
                                 BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.jwtAuthorizationFilter = jwtAuthorizationFilter;
        this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.userDetailsService = userDetailsService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(STATELESS)
                .and()
                .exceptionHandling()
                .accessDeniedHandler(jwtAccessDeniedHandler) // Fires when user tries to access a resource without having needed permission/s (role/s)
                .authenticationEntryPoint(jwtAuthenticationEntryPoint) // Fires when user tries to access a protected resource without supplying any credentials (Is not logged in)
                .and()
                .addFilterBefore(jwtAuthorizationFilter, AuthorizationFilter.class)
                .authorizeHttpRequests()
                .requestMatchers(PUBLIC_URLS).permitAll()
                .anyRequest().authenticated();
        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}
