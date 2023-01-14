package com.github.valhio.api.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.valhio.api.domain.HttpResponse;
import com.github.valhio.api.enumeration.Role;
import com.github.valhio.api.exception.ExceptionHandling;
import com.github.valhio.api.exception.domain.EmailExistException;
import com.github.valhio.api.exception.domain.NotAnImageFileException;
import com.github.valhio.api.exception.domain.PasswordNotMatchException;
import com.github.valhio.api.exception.domain.UsernameExistException;
import com.github.valhio.api.model.User;
import com.github.valhio.api.model.UserPrincipal;
import com.github.valhio.api.service.UserService;
import com.github.valhio.api.utility.JWTTokenProvider;
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Collection;
import java.util.Date;
import java.util.Map;
import java.util.Set;

import static com.github.valhio.api.constant.FileConstant.TEMP_PROFILE_IMAGE_BASE_URL;
import static com.github.valhio.api.constant.SecurityConstant.JWT_TOKEN_HEADER;
import static org.springframework.http.MediaType.IMAGE_JPEG_VALUE;

@RestController
@RequestMapping(path = {"/api/v1/user"})
public class UserController extends ExceptionHandling {

    private final UserService userService;
    private final AuthenticationManager authenticationManager;
    private final JWTTokenProvider jwtTokenProvider;

    public UserController(UserService userService, AuthenticationManager authenticationManager, JWTTokenProvider jwtTokenProvider) {
        this.userService = userService;
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @PostMapping("/register")
    public ResponseEntity<HttpResponse> register(@RequestBody User user) throws UsernameExistException, EmailExistException, IllegalArgumentException {
        User registered = userService.register(user);
        return ResponseEntity.ok(HttpResponse.builder()
                .timeStamp(new Date())
                .data(Map.of("user", registered))
                .message("User registered successfully")
                .status(HttpStatus.OK)
                .statusCode(HttpStatus.OK.value())
                .build());
    }

    // return response entity with jwt header
    @PostMapping("/login")
    public ResponseEntity<User> login(@RequestBody User user) throws UsernameExistException {
        authenticate(user.getUsername(), user.getPassword());
        User logged = userService.findUserByUsername(user.getUsername());
        UserPrincipal userPrincipal = new UserPrincipal(logged);
        HttpHeaders jwtHeader = getJwtHeader(userPrincipal);

        return ResponseEntity.ok()
                .headers(jwtHeader)
                .body(logged);
    }

    @PostMapping(path = "/add")
    public ResponseEntity<HttpResponse> addNewUser(@RequestPart(value = "profileImage") MultipartFile profileImage, @RequestParam String user) throws UsernameExistException, EmailExistException, IllegalArgumentException, IOException, NotAnImageFileException {
        ObjectMapper objectMapper = new ObjectMapper();
        User newUser = objectMapper.readValue(user, User.class);
        User registered = userService.addNewUser(newUser, profileImage);
        return ResponseEntity.ok(HttpResponse.builder()
                .timeStamp(new Date())
                .data(Map.of("user", registered))
                .message("User added successfully")
                .status(HttpStatus.OK)
                .statusCode(HttpStatus.OK.value())
                .build());
    }

    @GetMapping("/{username}")
    public ResponseEntity<HttpResponse> findUserByUsername(@PathVariable("username") String username) throws UsernameExistException {
        User user = userService.findUserByUsername(username);
        return ResponseEntity.ok(HttpResponse.builder()
                .timeStamp(new Date())
                .data(Map.of("user", user))
                .message("User retrieved successfully")
                .status(HttpStatus.OK)
                .statusCode(HttpStatus.OK.value())
                .build());
    }

    @GetMapping("/email/{email}")
    public ResponseEntity<HttpResponse> findUserByEmail(@PathVariable("email") String email) {
        User user = userService.findUserByEmail(email);
        return ResponseEntity.ok(HttpResponse.builder()
                .timeStamp(new Date())
                .data(Map.of("user", user))
                .message("User retrieved successfully")
                .status(HttpStatus.OK)
                .statusCode(HttpStatus.OK.value())
                .build());
    }

    @GetMapping("/list")
    public ResponseEntity<HttpResponse> getUsers() {
        return ResponseEntity.ok(HttpResponse.builder()
                .timeStamp(new Date())
                .data(Map.of("users", userService.getUsers()))
                .message("Users retrieved successfully")
                .status(HttpStatus.OK)
                .statusCode(HttpStatus.OK.value())
                .build());
    }

    @PostMapping("/update/{originalUsername}")
    public ResponseEntity<HttpResponse> update(@RequestPart(value = "profileImage", required = false) MultipartFile profileImage, @RequestParam String user, @PathVariable String originalUsername) throws EmailExistException, UsernameExistException, IOException, NotAnImageFileException {
        ObjectMapper objectMapper = new ObjectMapper();
        User newUser = objectMapper.readValue(user, User.class);
        User updated = userService.update(newUser, profileImage, originalUsername);
        return ResponseEntity.ok(HttpResponse.builder()
                .timeStamp(new Date())
                .data(Map.of("user", updated))
                .message("User updated successfully")
                .status(HttpStatus.OK)
                .statusCode(HttpStatus.OK.value())
                .build());
    }

    @DeleteMapping("/delete/{id}")
    @PreAuthorize("hasAnyAuthority('DELETE')")
    public ResponseEntity<HttpResponse> delete(@PathVariable("id") Long id) {
        userService.delete(id);
        return ResponseEntity.ok(HttpResponse.builder()
                .timeStamp(new Date())
                .message("User deleted successfully")
                .status(HttpStatus.OK)
                .statusCode(HttpStatus.OK.value())
                .build());
    }

    @DeleteMapping("/delete/userId/{userId}")
    @PreAuthorize("hasAnyAuthority('DELETE')")
    public ResponseEntity<HttpResponse> deleteByUserId(@PathVariable("userId") String userId) {
        userService.deleteByUserId(userId);
        return ResponseEntity.ok(HttpResponse.builder()
                .timeStamp(new Date())
                .message("User deleted successfully")
                .status(HttpStatus.OK)
                .statusCode(HttpStatus.OK.value())
                .build());
    }

    @GetMapping("/reset-password/{email}")
    public ResponseEntity<HttpResponse> resetPassword(@PathVariable("email") String email) {
        userService.resetPassword(email);
        return ResponseEntity.ok(HttpResponse.builder()
                .timeStamp(new Date())
                .data(Map.of("email", email))
                .message("Password reset successfully")
                .status(HttpStatus.OK)
                .statusCode(HttpStatus.OK.value())
                .build());
    }

    @PostMapping("/update-profile-image")
    public ResponseEntity<HttpResponse> updateProfileImage(@RequestParam("username") String username,
                                                           @RequestParam("profileImage") MultipartFile profileImage) throws IOException, UsernameExistException, NotAnImageFileException {
        userService.updateProfileImage(username, profileImage);
        return ResponseEntity.ok(HttpResponse.builder()
                .timeStamp(new Date())
                .data(Map.of("username", username, "profileImage", profileImage))
                .message("Profile image updated successfully")
                .status(HttpStatus.OK)
                .statusCode(HttpStatus.OK.value())
                .build());
    }

    @GetMapping(path = "/image/{username}/{fileName}", produces = IMAGE_JPEG_VALUE)
    public byte[] getProfileImage(@PathVariable("username") String username, @PathVariable String fileName) throws IOException {
        return userService.getProfileImage(username, fileName);
    }

    @GetMapping(path = "/image/profile/{username}", produces = IMAGE_JPEG_VALUE)
    public byte[] getTempProfileImage(@PathVariable("username") String username) throws IOException {
        URL url = new URL(TEMP_PROFILE_IMAGE_BASE_URL + username);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try (InputStream inputStream = url.openStream()) {
            int bytesRead;
            byte[] chunk = new byte[1024];
            while ((bytesRead = inputStream.read(chunk)) > 0) {
                byteArrayOutputStream.write(chunk, 0, bytesRead);
            }
        }
        return byteArrayOutputStream.toByteArray();
    }

    @PostMapping("/update-password")
    public ResponseEntity<HttpResponse> updatePassword(@RequestParam @NotBlank String username,
                                                       @RequestParam @NotBlank String currentPassword,
                                                       @RequestParam @NotBlank String newPassword) throws PasswordNotMatchException {
        userService.updatePassword(username, currentPassword, newPassword);
        return ResponseEntity.ok(HttpResponse.builder()
                .timeStamp(new Date())
                .message("Password updated successfully")
                .status(HttpStatus.OK)
                .statusCode(HttpStatus.OK.value())
                .build());
    }

    @PostMapping("/update-email")
    public ResponseEntity<HttpResponse> updateEmail(@RequestParam @NotBlank String username,
                                                    @RequestParam @NotBlank String currentPassword,
                                                    @RequestParam @NotBlank String newEmail) throws EmailExistException, PasswordNotMatchException {
        userService.updateEmail(username, currentPassword, newEmail);
        return ResponseEntity.ok(HttpResponse.builder()
                .timeStamp(new Date())
                .message("Email updated successfully")
                .status(HttpStatus.OK)
                .statusCode(HttpStatus.OK.value())
                .build());
    }

    @PostMapping("/update-username")
    public ResponseEntity<HttpResponse> updateUsername(@RequestParam @NotBlank String currentUsername,
                                                       @RequestParam @NotBlank String newUsername) throws UsernameExistException {
        userService.updateUsername(currentUsername, newUsername);
        return ResponseEntity.ok(HttpResponse.builder()
                .timeStamp(new Date())
                .message("Username updated successfully")
                .status(HttpStatus.OK)
                .statusCode(HttpStatus.OK.value())
                .build());
    }

    @GetMapping("/{username}/role")
    public ResponseEntity<HttpResponse> getUserRole(@PathVariable("username") String username) {
        Role role = userService.getUserRole(username);
        return ResponseEntity.ok(HttpResponse.builder()
                .timeStamp(new Date())
                .data(Map.of("role", role))
                .message("User role retrieved successfully")
                .status(HttpStatus.OK)
                .statusCode(HttpStatus.OK.value())
                .build());
    }

    @GetMapping("/{username}/authority")
    public ResponseEntity<HttpResponse> getUserAuthority(@PathVariable("username") String username) {
        Set<String> authorities = userService.getUserAuthorities(username);
        return ResponseEntity.ok(HttpResponse.builder()
                .timeStamp(new Date())
                .data(Map.of("authorities", authorities))
                .message("User authorities retrieved successfully")
                .status(HttpStatus.OK)
                .statusCode(HttpStatus.OK.value())
                .build());
    }

    @GetMapping("/list/role")
    public ResponseEntity<HttpResponse> getAllUsersByRole(@RequestParam String role) {
        Collection<User> users = userService.getUsersByRole(role);
        return ResponseEntity.ok(HttpResponse.builder()
                .timeStamp(new Date())
                .data(Map.of("users", users))
                .message("Users retrieved successfully")
                .status(HttpStatus.OK)
                .statusCode(HttpStatus.OK.value())
                .build());
    }

    //    @PostMapping("/add-role")
//    public ResponseEntity<HttpResponse> addRoleToUser(@RequestBody Map<String, Object> roleData) {
//        userService.addRoleToUser(roleData);
//        return ResponseEntity.ok(HttpResponse.builder()
//                .timeStamp(new Date())
//                .data(Map.of("roleData", roleData))
//                .message("Role added successfully")
//                .status(HttpStatus.OK)
//                .statusCode(HttpStatus.OK.value())
//                .build());
//    }
//
//    @PostMapping("/remove-role")
//    public ResponseEntity<HttpResponse> removeRoleFromUser(@RequestBody Map<String, Object> roleData) {
//        userService.removeRoleFromUser(roleData);
//        return ResponseEntity.ok(HttpResponse.builder()
//                .timeStamp(new Date())
//                .data(Map.of("roleData", roleData))
//                .message("Role removed successfully")
//                .status(HttpStatus.OK)
//                .statusCode(HttpStatus.OK.value())
//                .build());
//    }

    private HttpHeaders getJwtHeader(UserPrincipal user) {
        HttpHeaders headers = new HttpHeaders();
        headers.add(JWT_TOKEN_HEADER, jwtTokenProvider.generateJwtToken(user));
        return headers;
    }

    // Throws LockedException, DisabledException, BadCredentialsException, AccountExpiredException, CredentialsExpiredException ...
    // Locked exception is thrown if the UserPrincipal's isAccountNonLocked() method returns false.
    private void authenticate(String username, String password) {
        // Calls UserDetailsService.loadUserByUsername() to get the user
        // Then calls AuthenticationManager.authenticate() to authenticate the user
        // If the user is not authenticated, an exception is thrown and caught by the controller.
        // If the user is authenticated, the method returns and the user is logged in.
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
    }
}
