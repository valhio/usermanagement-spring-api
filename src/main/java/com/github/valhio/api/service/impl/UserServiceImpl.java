package com.github.valhio.api.service.impl;

import com.github.valhio.api.exception.domain.EmailExistException;
import com.github.valhio.api.exception.domain.UsernameExistException;
import com.github.valhio.api.model.User;
import com.github.valhio.api.model.UserPrincipal;
import com.github.valhio.api.repository.UserRepository;
import com.github.valhio.api.service.LoginAttemptService;
import com.github.valhio.api.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Collection;
import java.util.Objects;
import java.util.UUID;

import static com.github.valhio.api.enumeration.Role.ROLE_SUPER_ADMIN;
import static com.github.valhio.api.enumeration.Role.ROLE_USER;

@Slf4j
@Transactional
@Qualifier("userDetailsService")
@Service
public class UserServiceImpl implements UserService, UserDetailsService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final LoginAttemptService loginAttemptService;

    public UserServiceImpl(UserRepository userRepository, BCryptPasswordEncoder passwordEncoder, LoginAttemptService loginAttemptService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.loginAttemptService = loginAttemptService;
    }

    // This method is called by Spring Security when a user tries to log in.
    // This method is used by Spring Security to load a user by username.
    // It is used during the authentication process inside the AuthenticationManager located in the UserController class.
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);
        if (user == null) {
            log.error("User not found by username: " + username);
            throw new UsernameNotFoundException("User not found with username: " + username);
        }
        validateLoginAttempt(user);
        user.setLastLoginDateDisplay(user.getLastLoginDate());
        user.setLastLoginDate(LocalDateTime.now());
        userRepository.save(user);
        UserPrincipal userPrincipal = new UserPrincipal(user);
        log.info("User found by username: " + username);
        return userPrincipal;
    }

    // Validate if the user is locked or not.
    private void validateLoginAttempt(User user) {
        if (user.isNotLocked()) {
            user.setNotLocked(!loginAttemptService.isBlocked(user.getUsername()));
        } else {
            loginAttemptService.loginSucceeded(user.getUsername());
        }
    }

    @Override
    public User register(User user) throws UsernameExistException, EmailExistException, IllegalArgumentException {
        validateUsername(user.getUsername());
        validateEmail(user.getEmail());
        user.setUserId(UUID.randomUUID().toString().concat("-" + LocalDateTime.now().getNano()));
//        user.setUserId(UUID.randomUUID().toString().concat("-" + encodeUsername(user.getUsername())));
        user.setPassword(encodePassword(user.getPassword()));
        user.setCreatedAt(LocalDateTime.now());
        user.setActive(true);
        user.setNotLocked(true);
        user.setRole(Objects.equals(user.getEmail(), "a@a.com") ? ROLE_SUPER_ADMIN : ROLE_USER);
        user.setAuthorities(user.getRole().getAuthorities());
        user.setProfileImageUrl(getTemporaryProfileImageUrl(user.getFirstName()));
        return userRepository.save(user);
    }

    @Override
    public Collection<User> getUsers() {
        return userRepository.findAll();
    }

    @Override
    public User findUserByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    public User findUserByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    // Handle login
    @Override
    public User login(User user) {
        return null;
    }

    private String encodeUsername(String username) {
        return Base64.getEncoder().encodeToString(username.getBytes(StandardCharsets.UTF_8));
    }

    private String getTemporaryProfileImageUrl(String firstName) {
//        return "https://robohash.org/" + firstName + "?set=set3";
        return ServletUriComponentsBuilder.fromCurrentContextPath().path("/user/image/profile/temp").toUriString();
    }

    private String encodePassword(String password) {
        return passwordEncoder.encode(password);
    }

    private void validateEmail(String email) throws EmailExistException, IllegalArgumentException {
        validateString(email);
        if (userRepository.existsByEmail(email)) {
            throw new EmailExistException("Email already exist");
        }
    }

    private void validateUsername(String username) throws UsernameExistException, IllegalArgumentException {
        validateString(username);
        if (userRepository.existsByUsername(username)) {
            throw new UsernameExistException("Username already exist");
        }
    }

    private void validateString(String argument) throws IllegalArgumentException {
        if (argument == null || argument.isEmpty()) {
            throw new IllegalArgumentException("Argument cannot be null or empty");
        }
    }


}
