package com.example.opcua.server.basic;

import com.ttulka.opcua.spring.boot.auth.UsernameAuthenticator;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class OpcUaUsernameAuthServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(OpcUaUsernameAuthServerApplication.class, args);
	}

	@Bean
	UsernameAuthenticator usernameAuthenticator() {
		return auth -> "user".equals(auth.getUsername()) && "pass123".equals(auth.getPassword());
	}
}
