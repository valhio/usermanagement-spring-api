package com.github.valhio.api.listener;

import com.github.valhio.api.service.LoginAttemptService;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationFailureListener {

    private final LoginAttemptService loginAttemptService;

    public AuthenticationFailureListener(LoginAttemptService loginAttemptService) {
        this.loginAttemptService = loginAttemptService;
    }

    @EventListener
    public void onAuthenticationFailure(AuthenticationFailureBadCredentialsEvent event) {
//        WebAuthenticationDetails auth = (WebAuthenticationDetails) event.getAuthentication().getDetails(); // Get the IP address of the user who failed to log in.
//        WebAuthenticationDetails username = (WebAuthenticationDetails) event.getAuthentication().getPrincipal(); // Get the username of the user who failed to log in.
        String username = event.getAuthentication().getName(); // Get the username of the user who failed to log in.
        loginAttemptService.loginFailed(username);
    }
}
