package com.project.app.user.service;


import com.project.app.user.dto.UserDto;
import com.project.app.user.entity.User;
import org.springframework.http.ResponseEntity;

import java.util.List;

public interface UserService {
    Boolean saveUser(User user);

    User findByUsername(String username);

    List<User> findAllUsers();

    User getYourAccount(String authHeader) throws Exception;

    ResponseEntity<?> update(UserDto dto);

}
