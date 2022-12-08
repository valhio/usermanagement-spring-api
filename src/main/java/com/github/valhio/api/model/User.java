package com.github.valhio.api.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.io.Serializable;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import static jakarta.persistence.FetchType.EAGER;

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
    private String firstName;
    private String middleName;
    private String lastName;
    private String username;
    private String password;
    private String email;
    private String phone;
    private String profileImageUrl;
    private Date lastLoginDate;
    private Date lastLoginDateDisplay;
    private Date joinDate;
    private boolean isActive;
    private boolean isNotLocked; // Is the user's account verified via email?
    private String role;
    @ElementCollection(fetch = EAGER) // Eager fetches the authorities when the user is fetched, lazy fetches them when they are accessed
    private Set<String> authorities = new HashSet<>();

}
