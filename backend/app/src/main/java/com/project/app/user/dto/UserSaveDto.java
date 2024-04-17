package com.project.app.user.dto;


import com.project.app.user.entity.Role;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Getter
@Setter
@Data
public class UserSaveDto {

    private Long userId;

    @NotEmpty
    @NotNull
    @Size(min=3, max=30)
    private String name;

    @NotEmpty
    @NotNull
    private String surname;

    @NotEmpty
    @NotNull
    private String username;

    @NotEmpty
    @NotNull
    private String password;


    private String realPassword;

    @NotNull
    private Role role;
}
