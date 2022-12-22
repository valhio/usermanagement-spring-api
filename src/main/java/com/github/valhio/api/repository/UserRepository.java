package com.github.valhio.api.repository;

import com.github.valhio.api.enumeration.Role;
import com.github.valhio.api.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Collection;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    User findByUsername(String username); // Throws NoResultException if not found

    User findByEmail(String email);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    Collection<User> findAllByRole(Role role);
}
