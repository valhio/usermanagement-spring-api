package com.github.valhio.api.model;

import com.github.valhio.api.enumeration.Role;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.io.Serializable;
import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class User implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(nullable = false, updatable = false)
    private Long id;
    private String userId;

    private String username;

    //    @NotNull(message = "Password cannot be empty")
//    @Length(min = 7, message = "Password should be atleast 7 characters long")
    private String password;

    //    @NotNull(message = "First Name cannot be empty")
    @Column(name = "first_name")
    private String firstName;

    @Column(name = "middle_name")
    private String middleName;

    //    @NotNull(message = "Last Name cannot be empty")
    @Column(name = "last_name")
    private String lastName;

    //    @NotNull(message = "Email cannot be empty")
//    @Email(message = "Please enter a valid email address")
    private String email;

    //    @Length(min = 10, message = "Password should be atleast 10 number long")
    private String phone;

    private Boolean acceptedTerms;

    private String profileImageUrl;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    private int failedLoginAttempts;
    private LocalDateTime lastLoginDate;
    private LocalDateTime lastLoginDateDisplay;
    private boolean isActive;
    private boolean isNotLocked; // Is the user's account verified via email?

    @Enumerated(EnumType.STRING)
    private Role role;

    //    @ElementCollection(fetch = EAGER) // Eager fetches the authorities when the user is fetched, lazy fetches them when they are accessed
    private String[] authorities;

}
