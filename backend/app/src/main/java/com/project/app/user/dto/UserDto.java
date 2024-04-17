package com.project.app.user.dto;

import com.project.app.user.entity.Role;
import com.project.app.user.entity.User;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;


@Getter
@Setter
@Data
public class UserDto {
    private Long userId;
    private String name;
    private String surname;
    private String username;
    private Role role;
    private String password;
    private int status;

    public UserDto(){

    }
    public UserDto(User user){
        this.userId = user.getUserId();
        this.name = user.getName();
        this.surname = user.getSurname();
        this.username = user.getUsername();
        this.role = user.getRole();
        this.status = user.getStatus();
    }
}
