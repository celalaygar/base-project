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

@RestController
@RequestMapping(ApiPathConstant.BASE_PATH)
public class RoleApi {

	@GetMapping("/roles")
	public ResponseEntity<List<RoleDto>> getAllRoles() {
		List<Role> roles= Arrays.asList(Role.values());
		ArrayList<RoleDto> list= new ArrayList<>();
		roles.forEach(role->{
			list.add(new RoleDto(role, role.getValue()));
		});
		return ResponseEntity.ok(list);
	}

}
