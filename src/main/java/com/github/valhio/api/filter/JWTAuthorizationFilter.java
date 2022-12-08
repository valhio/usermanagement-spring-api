package com.github.valhio.api.filter;

import com.github.valhio.api.utility.JWTTokenProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

import static com.github.valhio.api.constant.SecurityConstant.OPTIONS_HTTP_METHOD;
import static com.github.valhio.api.constant.SecurityConstant.TOKEN_PREFIX;

/*
 *   This class is used to validate the JWT token sent by the client in the Authorization header of the request.
 * */

@NoArgsConstructor
@Component
public class JWTAuthorizationFilter extends OncePerRequestFilter {
    private JWTTokenProvider jwtTokenProvider;

    public JWTAuthorizationFilter(JWTTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (request.getMethod().equalsIgnoreCase(OPTIONS_HTTP_METHOD)) { // if the request is OPTIONS, then we allow it
            response.setStatus(HttpStatus.OK.value()); // we set the status to OK
        } else { // if the request is not OPTIONS, then we check if the request has a token
            String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION); // we get the authorization header

            // if the header is null or doesn't start with Bearer, we pass the request to the next filter
            if (authorizationHeader == null || !authorizationHeader.startsWith(TOKEN_PREFIX)) {
                filterChain.doFilter(request, response);
                return;
            }

            String token = authorizationHeader.substring(TOKEN_PREFIX.length()); // we get the token from the header
            String username = jwtTokenProvider.getSubject(token); // we get the username from the token

            // if the username is not null and the security context is empty, we set the authentication
            if (jwtTokenProvider.isTokenValid(username, token) && SecurityContextHolder.getContext().getAuthentication() == null) {
                List<? extends GrantedAuthority> authorities = jwtTokenProvider.getAuthorities(token); // we get the authorities from the token
                Authentication authentication = jwtTokenProvider.getAuthentication(username, authorities, request); // we get the authentication from the token
                SecurityContextHolder.getContext().setAuthentication(authentication); // we set the authentication in the security context
            } else {
                SecurityContextHolder.clearContext(); // if the token is not valid, we clear the security context
            }
            filterChain.doFilter(request, response); // we pass the request to the next filter
        }
    }
}
