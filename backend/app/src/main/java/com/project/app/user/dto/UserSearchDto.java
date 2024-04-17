package com.project.app.user.dto;

import com.project.app.user.entity.Role;
import lombok.Data;

@Data
public class UserSearchDto {

    private Long userId;
    private String name;
    private String surname;
    private String username;
    private String password;
    private Role role;
}
