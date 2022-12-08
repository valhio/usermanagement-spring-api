package com.github.valhio.api.service.impl;

import com.github.valhio.api.model.User;
import com.github.valhio.api.model.UserPrincipal;
import com.github.valhio.api.repository.UserRepository;
import com.github.valhio.api.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.logging.Logger;

@Slf4j
@Transactional
@Qualifier("userDetailsService")
@Service
public class UserServiceImpl implements UserService, UserDetailsService {
    private final UserRepository userRepository;

    public UserServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);
        if (user == null) {
            log.error("User not found by username: " + username);
            throw new UsernameNotFoundException("User not found with username: " + username);
        }

        log.info("User found by username: " + username);
        user.setLastLoginDateDisplay(user.getLastLoginDate());
        user.setLastLoginDate(new Date());
        return new UserPrincipal(userRepository.save(user));
    }
}
