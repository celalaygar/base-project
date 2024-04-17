package com.project.app.user.repository;

import com.project.app.user.entity.Role;
import com.project.app.user.entity.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);
    List<User> findByRole(Role role);
    List<User> findByRole(Role role, Sort sort);
    List<User> findByUsernameNot(String username, Sort sort);
    Page<User> findByUsernameNot(String username,  Pageable page);



}

