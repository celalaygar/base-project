package com.project.app.auth.dto;

import lombok.*;

@Getter
@Setter
@Data
@ToString
@NoArgsConstructor
@AllArgsConstructor
public class AuthRequestDto {
	
	private String username;
	private String password;

}
