package com.project.app.auth.api;


import com.project.app.auth.dto.AuthRequestDto;
import com.project.app.auth.dto.AuthResponseDto;
import com.project.app.auth.dto.RoleDto;
import com.project.app.auth.service.JwtService;
import com.project.app.user.entity.Role;
import com.project.app.user.entity.User;
import com.project.app.user.service.UserServiceImpl;
import com.project.app.util.ApiPathConstant;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping(ApiPathConstant.BASE_PATH)
public class LoginApi {
	@Autowired
	private AuthenticationManager authenticationManager;
    @Autowired
    private JwtService jwtService;
    @Autowired
    private UserServiceImpl userService;

	@PostMapping("/login")
	public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthRequestDto autRequest) throws Exception {
		try {
			Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
					autRequest.getUsername(), autRequest.getPassword()));

			if(!authentication.isAuthenticated()){
				return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("UNAUTHORIZED");
			}
			SecurityContextHolder.getContext().setAuthentication(authentication);
			String jwt = jwtService.generateToken(authentication);
			String username = autRequest.getUsername();
			User user = userService.findByUsername(username);

			if(user == null){
				return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("UNAUTHORIZED");
			}

			return ResponseEntity.ok(new AuthResponseDto(user.getUserId(), username,jwt,null,user.getRole()));
		}catch (Exception e) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("UNAUTHORIZED");
		}
	}


}
