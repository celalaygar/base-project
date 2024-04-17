package com.project.app.user.service;

import com.project.app.auth.service.JwtService;
import com.project.app.user.entity.User;
import com.project.app.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class ControlService {
	private final JwtService jwtService;
	private final UserRepository userRepository;

	public User getUserFromToken(String token) throws Exception {
		String username = getUsernameFromToken(token);
		Optional<User> opt = userRepository.findByUsername(username);
		if (!opt.isPresent()) {
			throw new Exception("There is no user with " + username);
		}
		return opt.get();
	}
	public String getUsernameFromToken(String authHeader) {
		String username= null;
		if(authHeader != null ) {
			username = jwtService.extractUsername(authHeader);
		}
		return username;
	}
}
