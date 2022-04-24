package com.example.opcua.server.basic;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.util.Scanner;

@SpringBootApplication
public class OpcUaBasicServerApplication implements CommandLineRunner {

	public static void main(String[] args) {
		SpringApplication.run(OpcUaBasicServerApplication.class, args);
	}

	@Override
	public void run(String... args) {
		System.out.println("\nPress any enter to stop the OPC UA Server and quit...");
		new Scanner(System.in).nextLine();
	}
}
