package com.github.valhio.api.controller;

import com.github.valhio.api.domain.HttpResponse;
import com.github.valhio.api.exception.ExceptionHandling;
import com.github.valhio.api.exception.domain.EmailExistException;
import com.github.valhio.api.exception.domain.UsernameExistException;
import com.github.valhio.api.model.User;
import com.github.valhio.api.model.UserPrincipal;
import com.github.valhio.api.service.UserService;
import com.github.valhio.api.utility.JWTTokenProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Date;
import java.util.Map;

import static com.github.valhio.api.constant.SecurityConstant.JWT_TOKEN_HEADER;

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
    public ResponseEntity<HttpResponse> login(@RequestBody User user) {
        authenticate(user.getUsername(), user.getPassword());
        User logged = userService.findUserByUsername(user.getUsername());
        UserPrincipal userPrincipal = new UserPrincipal(logged);
        HttpHeaders jwtHeader = getJwtHeader(userPrincipal);

        return ResponseEntity.ok()
                .headers(jwtHeader)
                .body(HttpResponse.builder()
                        .timeStamp(new Date())
                        .data(Map.of("user", logged))
                        .message("User logged in successfully")
                        .status(HttpStatus.OK)
                        .statusCode(HttpStatus.OK.value())
                        .build());
    }

//    @PostMapping("/add")
//    public ResponseEntity<HttpResponse> addNewUser(@RequestBody User user) throws UsernameExistException, EmailExistException, IllegalArgumentException {
//        User registered = userService.addNewUser(user);
//        return ResponseEntity.ok(HttpResponse.builder()
//                .timeStamp(new Date())
//                .data(Map.of("user", registered))
//                .message("User added successfully")
//                .status(HttpStatus.OK)
//                .statusCode(HttpStatus.OK.value())
//                .build());
//    }
//
//    @GetMapping("/find/{username}")
//    public ResponseEntity<HttpResponse> findUserByUsername(@PathVariable("username") String username) {
//        User user = userService.findUserByUsername(username);
//        return ResponseEntity.ok(HttpResponse.builder()
//                .timeStamp(new Date())
//                .data(Map.of("user", user))
//                .message("User retrieved successfully")
//                .status(HttpStatus.OK)
//                .statusCode(HttpStatus.OK.value())
//                .build());
//    }
//
//    @GetMapping("/find/email/{email}")
//    public ResponseEntity<HttpResponse> findUserByEmail(@PathVariable("email") String email) {
//        User user = userService.findUserByEmail(email);
//        return ResponseEntity.ok(HttpResponse.builder()
//                .timeStamp(new Date())
//                .data(Map.of("user", user))
//                .message("User retrieved successfully")
//                .status(HttpStatus.OK)
//                .statusCode(HttpStatus.OK.value())
//                .build());
//    }
//
//    @GetMapping("/list")
//    public ResponseEntity<HttpResponse> getUsers() {
//        return ResponseEntity.ok(HttpResponse.builder()
//                .timeStamp(new Date())
//                .data(Map.of("users", userService.getUsers()))
//                .message("Users retrieved successfully")
//                .status(HttpStatus.OK)
//                .statusCode(HttpStatus.OK.value())
//                .build());
//    }
//
//    @PostMapping("/update")
//    public ResponseEntity<HttpResponse> update(@RequestBody User user) {
//        User updated = userService.update(user);
//        return ResponseEntity.ok(HttpResponse.builder()
//                .timeStamp(new Date())
//                .data(Map.of("user", updated))
//                .message("User updated successfully")
//                .status(HttpStatus.OK)
//                .statusCode(HttpStatus.OK.value())
//                .build());
//    }
//
//    @DeleteMapping("/delete/{id}")
//    public ResponseEntity<HttpResponse> delete(@PathVariable("id") Long id) {
//        userService.delete(id);
//        return ResponseEntity.ok(HttpResponse.builder()
//                .timeStamp(new Date())
//                .data(Map.of("id", id))
//                .message("User deleted successfully")
//                .status(HttpStatus.OK)
//                .statusCode(HttpStatus.OK.value())
//                .build());
//    }
//
//    @GetMapping("/reset-password/{email}")
//    public ResponseEntity<HttpResponse> resetPassword(@PathVariable("email") String email) {
//        userService.resetPassword(email);
//        return ResponseEntity.ok(HttpResponse.builder()
//                .timeStamp(new Date())
//                .data(Map.of("email", email))
//                .message("Password reset successfully")
//                .status(HttpStatus.OK)
//                .statusCode(HttpStatus.OK.value())
//                .build());
//    }
//
//    @PostMapping("/update-profile-image")
//    public ResponseEntity<HttpResponse> updateProfileImage(@RequestParam("username") String username,
//                                                           @RequestParam("profileImage") MultipartFile profileImage) throws IOException {
//        userService.updateProfileImage(username, profileImage);
//        return ResponseEntity.ok(HttpResponse.builder()
//                .timeStamp(new Date())
//                .data(Map.of("username", username, "profileImage", profileImage))
//                .message("Profile image updated successfully")
//                .status(HttpStatus.OK)
//                .statusCode(HttpStatus.OK.value())
//                .build());
//    }
//
//    @GetMapping("/image/{username}/{fileName}")
//    public byte[] getProfileImage(@PathVariable("username") String username, @PathVariable("fileName") String fileName) throws IOException {
//        return userService.getProfileImage(username, fileName);
//    }
//
//    @GetMapping("/image/{username}")
//    public byte[] getTemporaryProfileImage(@PathVariable("username") String username) throws IOException {
//        return userService.getTemporaryProfileImage(username);
//    }
//
//    @PostMapping("/update-password")
//    public ResponseEntity<HttpResponse> updatePassword(@RequestBody Map<String, Object> passwordData) {
//        userService.updatePassword(passwordData);
//        return ResponseEntity.ok(HttpResponse.builder()
//                .timeStamp(new Date())
//                .data(Map.of("passwordData", passwordData))
//                .message("Password updated successfully")
//                .status(HttpStatus.OK)
//                .statusCode(HttpStatus.OK.value())
//                .build());
//    }
//
//    @PostMapping("/update-email")
//    public ResponseEntity<HttpResponse> updateEmail(@RequestBody Map<String, Object> emailData) {
//        userService.updateEmail(emailData);
//        return ResponseEntity.ok(HttpResponse.builder()
//                .timeStamp(new Date())
//                .data(Map.of("emailData", emailData))
//                .message("Email updated successfully")
//                .status(HttpStatus.OK)
//                .statusCode(HttpStatus.OK.value())
//                .build());
//    }
//
//    @PostMapping("/update-username")
//    public ResponseEntity<HttpResponse> updateUsername(@RequestBody Map<String, Object> usernameData) {
//        userService.updateUsername(usernameData);
//        return ResponseEntity.ok(HttpResponse.builder()
//                .timeStamp(new Date())
//                .data(Map.of("usernameData", usernameData))
//                .message("Username updated successfully")
//                .status(HttpStatus.OK)
//                .statusCode(HttpStatus.OK.value())
//                .build());
//    }
//
//    @GetMapping("/user/{username}")
//    public ResponseEntity<HttpResponse> getUser(@PathVariable("username") String username) {
//        User user = userService.getUser(username);
//        return ResponseEntity.ok(HttpResponse.builder()
//                .timeStamp(new Date())
//                .data(Map.of("user", user))
//                .message("User retrieved successfully")
//                .status(HttpStatus.OK)
//                .statusCode(HttpStatus.OK.value())
//                .build());
//    }
//
//    @GetMapping("/user/{username}/role")
//    public ResponseEntity<HttpResponse> getUserRole(@PathVariable("username") String username) {
//        List<Role> roles = userService.getUserRoles(username);
//        return ResponseEntity.ok(HttpResponse.builder()
//                .timeStamp(new Date())
//                .data(Map.of("roles", roles))
//                .message("User roles retrieved successfully")
//                .status(HttpStatus.OK)
//                .statusCode(HttpStatus.OK.value())
//                .build());
//    }
//
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
//
//    @GetMapping("/list/{role}")
//    public ResponseEntity<HttpResponse> getAllUsersByRole(@PathVariable("role") String role) {
//        List<User> users = userService.getUsersByRole(role);
//        return ResponseEntity.ok(HttpResponse.builder()
//                .timeStamp(new Date())
//                .data(Map.of("users", users))
//                .message("Users retrieved successfully")
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
