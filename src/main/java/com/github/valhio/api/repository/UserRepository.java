package com.github.valhio.api.repository;

import com.github.valhio.api.enumeration.Role;
import com.github.valhio.api.model.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    User findByUsername(String username); // Throws NoResultException if not found

    User findByEmail(String email);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    Collection<User> findAllByRole(Role role);

    Optional<User> findByUserId(String userId);

    @Query(value = "SELECT u FROM User u WHERE CONCAT(u.userId ,u.username, u.firstName, u.lastName, u.email) LIKE %?1%")
    Page<User> findAll(String keyword, Pageable pageable);
}
