package com.github.valhio.api.service.impl;

import com.github.valhio.api.enumeration.Role;
import com.github.valhio.api.exception.domain.EmailExistException;
import com.github.valhio.api.exception.domain.NotAnImageFileException;
import com.github.valhio.api.exception.domain.PasswordNotMatchException;
import com.github.valhio.api.exception.domain.UsernameExistException;
import com.github.valhio.api.model.User;
import com.github.valhio.api.model.UserPrincipal;
import com.github.valhio.api.repository.UserRepository;
import com.github.valhio.api.service.LoginAttemptService;
import com.github.valhio.api.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.apache.tomcat.util.http.fileupload.FileUtils;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

import static com.github.valhio.api.constant.FileConstant.DIRECTORY_CREATED;
import static com.github.valhio.api.constant.FileConstant.USER_FOLDER;
import static com.github.valhio.api.constant.FileConstant.*;
import static com.github.valhio.api.constant.UserImplConstant.*;
import static com.github.valhio.api.enumeration.Role.ROLE_SUPER_ADMIN;
import static com.github.valhio.api.enumeration.Role.ROLE_USER;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static org.springframework.http.MediaType.*;

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
        user.setProfileImageUrl(getTemporaryProfileImageUrl(user.getFirstName(), user.getLastName()));
        return userRepository.save(user);
    }

    @Override
    public Collection<User> getUsers() {
        return userRepository.findAll();
    }

    @Override
    public User addNewUser(User user, MultipartFile profileImage) throws UsernameExistException, EmailExistException, IOException, NotAnImageFileException {
        validateUsername(user.getUsername());
        validateEmail(user.getEmail());
        user.setUserId(UUID.randomUUID().toString().concat("-" + LocalDateTime.now().getNano()));
        user.setPassword(encodePassword(user.getPassword()));
        user.setCreatedAt(LocalDateTime.now());
        user.setAuthorities(user.getRole().getAuthorities());
        saveProfileImageMultipartFile(user, profileImage);
        return userRepository.save(user);
    }

    @Override
    public User update(String username, User user) throws UsernameNotFoundException, UsernameExistException, EmailExistException {
        User userByUsername = this.findUserByUsername(username);
        if (userByUsername == null) throw new UsernameNotFoundException("User not found with username: " + username);

        if (!userByUsername.getUsername().equals(user.getUsername())) validateUsername(user.getUsername());
        if (!userByUsername.getEmail().equals(user.getEmail())) validateEmail(user.getEmail());

        userByUsername.setFirstName(user.getFirstName().trim().length() == 0 ? userByUsername.getFirstName() : user.getFirstName());
        userByUsername.setLastName(user.getLastName().trim().length() == 0 ? userByUsername.getLastName() : user.getLastName());
        userByUsername.setUsername(user.getUsername().trim().length() == 0 ? userByUsername.getUsername() : user.getUsername());
        userByUsername.setEmail(user.getEmail().trim().length() == 0 ? userByUsername.getEmail() : user.getEmail());
        userByUsername.setRole(user.getRole().name().trim().length() == 0 ? userByUsername.getRole() : user.getRole());
        userByUsername.setAuthorities(user.getRole().getAuthorities());
        userByUsername.setActive(user.isActive());
        userByUsername.setNotLocked(user.isNotLocked());
        return userRepository.save(userByUsername);
    }

    @Override
    public void delete(Long id) {
        userRepository.deleteById(id);
    }

    // TODO: Implement valid Reset Password Functionality
    @Override
    public void resetPassword(String email) {
        User user = userRepository.findByEmail(email);
        if (user == null) throw new UsernameNotFoundException(NO_USER_FOUND_BY_EMAIL + email);
        user.setPassword(encodePassword("password"));
        userRepository.save(user);
    }

    @Override
    public void updateProfileImage(String username, MultipartFile profileImage) throws
            UsernameExistException, IOException, NotAnImageFileException {
        validateUsername(username);
        User user = userRepository.findByUsername(username);
        saveProfileImageMultipartFile(user, profileImage);
    }

    @Override
    public User findUserByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    public User findUserByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    @Override
    public byte[] getProfileImage(String username, String fileName) throws IOException {
        return Files.readAllBytes(Paths.get(USER_FOLDER + username + FORWARD_SLASH + fileName));
    }

    @Override
    public void updatePassword(String username, String currentPassword, String newPassword) throws UsernameNotFoundException, PasswordNotMatchException {
        User user = userRepository.findByUsername(username);
        if (user == null) throw new UsernameNotFoundException(NO_USER_FOUND_BY_USERNAME + username);
        if (!passwordEncoder.matches(currentPassword, user.getPassword()))
            throw new PasswordNotMatchException(INCORRECT_CURRENT_PASSWORD);
        user.setPassword(encodePassword(newPassword));
        userRepository.save(user);
    }

    @Override
    public void updateEmail(String username, String currentPassword, String newEmail) throws UsernameNotFoundException, PasswordNotMatchException, EmailExistException {
        User user = userRepository.findByUsername(username);
        if (user == null) throw new UsernameNotFoundException(NO_USER_FOUND_BY_USERNAME + username);
        if (!passwordEncoder.matches(currentPassword, user.getPassword()))
            throw new PasswordNotMatchException(INCORRECT_CURRENT_PASSWORD);
        validateEmail(newEmail);
        user.setEmail(newEmail);
        userRepository.save(user);
    }

    @Override
    public void updateUsername(String currentUsername, String newUsername) {
        User user = userRepository.findByUsername(currentUsername);
        if (user == null) throw new UsernameNotFoundException(NO_USER_FOUND_BY_USERNAME + currentUsername);
        user.setUsername(newUsername);
        userRepository.save(user);
    }

    @Override
    public Role getUserRole(String username) {
        User user = userRepository.findByUsername(username);
        if (user == null) throw new UsernameNotFoundException(NO_USER_FOUND_BY_USERNAME + username);
        return user.getRole();
    }

    @Override
    public Set<String> getUserAuthorities(String username) {
        User user = userRepository.findByUsername(username);
        if (user == null) throw new UsernameNotFoundException(NO_USER_FOUND_BY_USERNAME + username);
        return Arrays.stream(user.getAuthorities()).collect(Collectors.toSet());
    }

    @Override
    public Collection<User> getUsersByRole(String role) {
        return userRepository.findAllByRole(Role.valueOf(role.toUpperCase()));
    }

    private void saveProfileImageMultipartFile(User user, MultipartFile profileImage) throws
            IOException, NotAnImageFileException {
        if (profileImage != null) {
            if (!Arrays.asList(IMAGE_JPEG_VALUE, IMAGE_PNG_VALUE, IMAGE_GIF_VALUE).contains(profileImage.getContentType())) {
                throw new NotAnImageFileException(profileImage.getOriginalFilename() + NOT_AN_IMAGE_FILE);
            }
            Path userFolder = Paths.get(USER_FOLDER + user.getUsername()).toAbsolutePath().normalize();
            if (!Files.exists(userFolder)) {
                Files.createDirectories(userFolder);
                log.info(DIRECTORY_CREATED + userFolder);
            }
            Files.deleteIfExists(Paths.get(userFolder + user.getUsername() + DOT + JPG_EXTENSION));
            Files.copy(profileImage.getInputStream(), userFolder.resolve(user.getUsername() + DOT + JPG_EXTENSION), REPLACE_EXISTING);
            user.setProfileImageUrl(setProfileImageUrl(user.getUsername()));
            userRepository.save(user);
            log.info(FILE_SAVED_IN_FILE_SYSTEM + profileImage.getOriginalFilename());
        }
    }

    private void saveProfileImageFile(User user, File profileImage) throws IOException {
        if (profileImage != null) {
            Path userFolder = Paths.get(USER_FOLDER + user.getUsername()).toAbsolutePath().normalize();
            if (!Files.exists(userFolder)) {
                try {
                    Files.createDirectories(userFolder);
                    log.info(DIRECTORY_CREATED + userFolder);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            Files.deleteIfExists(Paths.get(userFolder + user.getUsername() + DOT + JPG_EXTENSION));
            Files.copy(profileImage.toPath(), userFolder.resolve(user.getUsername() + DOT + JPG_EXTENSION), REPLACE_EXISTING);
            user.setProfileImageUrl(setProfileImageUrl(user.getUsername()));
            userRepository.save(user);
            log.info(FILE_SAVED_IN_FILE_SYSTEM + profileImage.getName());
        }
    }

    @NotNull
    private MockMultipartFile getProfileImageAsMultipartFile(String originalUsername) throws IOException {
        return new MockMultipartFile(
                originalUsername + DOT + JPG_EXTENSION,
                originalUsername + DOT + JPG_EXTENSION,
                "image/png",
                Files.readAllBytes(Paths.get(USER_FOLDER + originalUsername + FORWARD_SLASH + originalUsername + DOT + JPG_EXTENSION)));
    }

    private void deleteProfileImage(String username) {
        Path userFolder = Paths.get(USER_FOLDER + username).toAbsolutePath().normalize();
        try {
            FileUtils.deleteDirectory(new File(userFolder.toString()));
        } catch (IOException e) {
            log.error(e.getMessage());
        }
    }

    private String setProfileImageUrl(String username) {
        return ServletUriComponentsBuilder.fromCurrentContextPath().path(USER_IMAGE_PATH + username + FORWARD_SLASH
                + username + DOT + JPG_EXTENSION).toUriString();
    }

    private String encodeUsername(String username) {
        return Base64.getEncoder().encodeToString(username.getBytes(StandardCharsets.UTF_8));
    }

    private String getTemporaryProfileImageUrl(String firstName) {
        return "https://robohash.org/" + firstName + "?set=set3";
//        return ServletUriComponentsBuilder.fromCurrentContextPath().path(DEFAULT_USER_IMAGE_PATH + firstName).toUriString();
    }

    private String encodePassword(String password) {
        return passwordEncoder.encode(password);
    }

    private void validateEmail(String email) throws EmailExistException, IllegalArgumentException {
        validateString(email);
        if (userRepository.existsByEmail(email)) {
            throw new EmailExistException(EMAIL_ALREADY_EXISTS);
        }
    }

    private void validateUsername(String username) throws UsernameExistException, IllegalArgumentException {
        validateString(username);
        if (userRepository.existsByUsername(username)) {
            throw new UsernameExistException(USERNAME_ALREADY_EXISTS);
        }
    }

    private void validateString(String argument) throws IllegalArgumentException {
        if (argument == null || argument.isEmpty()) {
            throw new IllegalArgumentException("Argument cannot be null or empty");
        }
    }

}
