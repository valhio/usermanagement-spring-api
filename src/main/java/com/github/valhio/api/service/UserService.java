package com.github.valhio.api.service;

import com.github.valhio.api.exception.domain.EmailExistException;
import com.github.valhio.api.exception.domain.UserNotFoundException;
import com.github.valhio.api.exception.domain.UsernameExistException;
import com.github.valhio.api.model.User;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Collection;

public interface UserService {
    public User register(User user) throws UsernameExistException, EmailExistException, IllegalArgumentException;

    public Collection<User> getUsers();

    public User findUserByUsername(String username);

    public User findUserByEmail(String email);


    User login(User user);
}
