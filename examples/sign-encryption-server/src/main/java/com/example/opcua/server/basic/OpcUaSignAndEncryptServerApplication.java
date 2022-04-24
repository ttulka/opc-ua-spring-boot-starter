package com.example.opcua.server.basic;

import org.eclipse.milo.opcua.sdk.server.identity.UsernameIdentityValidator;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.util.Scanner;

@SpringBootApplication
public class OpcUaSignAndEncryptServerApplication implements CommandLineRunner {

	public static void main(String[] args) {
		SpringApplication.run(OpcUaSignAndEncryptServerApplication.class, args);
	}

	@Override
	public void run(String... args) {
		System.out.println("\nPress any enter to stop the OPC UA Server and quit...");
		new Scanner(System.in).nextLine();
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
