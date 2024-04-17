package com.project.app.auth.dto;


import com.project.app.user.entity.Role;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class RoleDto {
    Role role;
    String value;


}
