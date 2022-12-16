package com.github.valhio.api.listener;

import com.github.valhio.api.model.UserPrincipal;
import com.github.valhio.api.service.LoginAttemptService;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationSuccessListener {

    private final LoginAttemptService loginAttemptService;

    public AuthenticationSuccessListener(LoginAttemptService loginAttemptService) {
        this.loginAttemptService = loginAttemptService;
    }

    @EventListener
    public void onAuthenticationSuccess(AuthenticationSuccessEvent event) {
//        event.getAuthentication().getDetails(); // Get the IP address of the user who successfully logged in.
//        String username = event.getAuthentication().getName();// Get the username of the user who successfully logged in.
        Object user = event.getAuthentication().getPrincipal(); // Get the username of the user who successfully logged in.
        if (user instanceof UserPrincipal) loginAttemptService.loginSucceeded(((UserPrincipal) user).getUsername());
    }

}
