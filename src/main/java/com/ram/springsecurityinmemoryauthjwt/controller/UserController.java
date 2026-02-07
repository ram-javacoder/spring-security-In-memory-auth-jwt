package com.ram.springsecurityinmemoryauthjwt.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

	@GetMapping("/welcome")
	public String welcome(Authentication authentication) {
		String userName = authentication.getName();
		return "Welcome " + userName + " to Spring Security In-Memory Authentication Example";
	}
	
	@GetMapping("/public")
	public String publicApi() {
	    return "Public API - No Authentication Required";
	}
}
