package com.ram.springsecurityinmemoryauthjwt.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ram.springsecurityinmemoryauthjwt.dto.AuthRequest;
import com.ram.springsecurityinmemoryauthjwt.dto.AuthResponse;
import com.ram.springsecurityinmemoryauthjwt.dto.RefreshRequest;
import com.ram.springsecurityinmemoryauthjwt.util.JwtUtil;

@RestController
@RequestMapping("/auth")
public class AuthController {

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private JwtUtil jwtUtil;

	@Autowired
	private UserDetailsService userDetailsService;
	
	
	@PostMapping("/login")
	public AuthResponse login(@RequestBody AuthRequest request) {

		Authentication authentication = authenticationManager
				.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
	
	
		UserDetails userDetails = (UserDetails) authentication.getPrincipal();

	    List<String> roles = userDetails.getAuthorities()
	            .stream()
	            .map(auth -> auth.getAuthority())
	            .toList();
	    
	    String accessToken =
	            jwtUtil.generateAccessToken(
	                    userDetails.getUsername(), roles);

	    String refreshToken =
	            jwtUtil.generateRefreshToken(
	                    userDetails.getUsername());
	    
	    return new AuthResponse(accessToken, refreshToken);
	
	}
	
	@PostMapping("/refresh")
	public String refreshToken(@RequestBody RefreshRequest request) {

		 String token = request.getRefreshToken();

		    String username =
		            jwtUtil.extractAllClaims(token)
		                   .getSubject();

		    UserDetails userDetails =
		            userDetailsService.loadUserByUsername(username);

		    List<String> roles = userDetails.getAuthorities()
		            .stream()
		            .map(a -> a.getAuthority())
		            .toList();

		    return jwtUtil.generateAccessToken(username, roles);
	}
	
}


