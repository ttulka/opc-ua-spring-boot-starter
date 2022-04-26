package com.example.opcua.server.basic;

import org.eclipse.milo.opcua.sdk.server.identity.UsernameIdentityValidator;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class OpcUaSignAndEncryptServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(OpcUaSignAndEncryptServerApplication.class, args);
	}

	@Bean
	UsernameIdentityValidator usernameIdentityValidator() {
		return new UsernameIdentityValidator(false, authChallenge -> {
			String username = authChallenge.getUsername();
			String password = authChallenge.getPassword();

			boolean userOk = "user".equals(username) && "password1".equals(password);
			boolean adminOk = "admin".equals(username) && "password2".equals(password);

			return userOk || adminOk;
		});
	}
}
