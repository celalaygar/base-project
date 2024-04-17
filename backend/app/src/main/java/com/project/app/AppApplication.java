package com.project.app;

import com.project.app.user.entity.Role;
import com.project.app.user.entity.User;
import com.project.app.user.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Date;

@SpringBootApplication
public class AppApplication {


	public static void main(String[] args) {
		SpringApplication.run(AppApplication.class, args);
	}



	@Bean
	CommandLineRunner createInitialUsers(UserRepository usereRepository,
										 PasswordEncoder passwordEncoder) {
		return (args) -> {
			try {

				User user1 = new User();
				user1.setName("BY admin");
				user1.setSurname("extra");
				user1.setUsername("admin");
				user1.setStatus(1);
				user1.setPassword(passwordEncoder.encode( "admin123"));
				user1.setRole(Role.ADMIN);
				usereRepository.save(user1);

				User user2 = new User();
				user2.setName("manager");
				user2.setSurname("manager serr");
				user2.setUsername("manager");
				user2.setStatus(1);
				user2.setPassword(passwordEncoder.encode( "managerrqr"));
				user2.setRole(Role.MANAGER);
				usereRepository.save(user2);

			} catch (Exception e) {
				System.out.println(e);
			}
		};
	}
}
