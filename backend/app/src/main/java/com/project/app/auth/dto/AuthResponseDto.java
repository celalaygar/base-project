package com.project.app.auth.dto;

import com.project.app.user.entity.Role;
import lombok.*;

import java.io.Serializable;

@Data
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class AuthResponseDto implements Serializable{
	private Long userId;
	private String username;
	private String jwttoken;
	private String email;
	private Role role;
}
