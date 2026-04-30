package com.freelanceplatform.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AuthApplication {

	public static void main(String[] args) {
        System.out.println("Auth Service Started");
        SpringApplication.run(AuthApplication.class, args);
    }

}
