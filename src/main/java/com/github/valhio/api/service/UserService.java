package com.github.valhio.api.service;

import com.github.valhio.api.enumeration.Role;
import com.github.valhio.api.exception.domain.EmailExistException;
import com.github.valhio.api.exception.domain.NotAnImageFileException;
import com.github.valhio.api.exception.domain.PasswordNotMatchException;
import com.github.valhio.api.exception.domain.UsernameExistException;
import com.github.valhio.api.model.User;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Collection;
import java.util.Set;

public interface UserService {
    public User register(User user) throws UsernameExistException, EmailExistException, IllegalArgumentException;

    User addNewUser(User user, MultipartFile profileImage) throws UsernameExistException, EmailExistException, IOException, NotAnImageFileException;

    User findUserByUsername(String username) throws UsernameExistException;

    User findUserByEmail(String email);

    Collection<User> getUsers();

    User update(User newUser, MultipartFile newProfileImage, String originalUsername) throws UsernameExistException, EmailExistException, IOException, NotAnImageFileException;

    void delete(Long id);

    void deleteByUserId(String userId);

    void resetPassword(String email);

    void updateProfileImage(String username, MultipartFile profileImage) throws UsernameExistException, IOException, NotAnImageFileException;

    byte[] getProfileImage(String username, String fileName) throws IOException;

    void updatePassword(String username, String currentPassword, String newPassword) throws PasswordNotMatchException;

    void updateEmail(String username, String currentPassword, String newEmail) throws PasswordNotMatchException, EmailExistException;

    void updateUsername(String currentUsername, String newUsername);

    Role getUserRole(String username);

    Collection<User> getUsersByRole(String role);

    Set<String> getUserAuthorities(String username);

//    void AddRoleToUser(String username, String role);
//
//    void removeRoleFromUser(String username, String role);
}
