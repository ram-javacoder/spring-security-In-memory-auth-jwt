package com.ram.springsecurityinmemoryauthjwt.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.ram.springsecurityinmemoryauthjwt.filter.JwtAuthFilter;
import com.ram.springsecurityinmemoryauthjwt.util.JwtUtil;

@Configuration
public class SecurityConfig {

	@Autowired
	private JwtUtil jwtUtil;

	@Value("${app.security.user.username}")
	private String userName;

	@Value("${app.security.user.password}")
	private String userPassword;

	@Value("${app.security.admin.username}")
	private String adminName;

	@Value("${app.security.admin.password}")
	private String adminPassword;

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public JwtAuthFilter jwtAuthFilter(UserDetailsService userDetailsService, JwtUtil jwtUtil) {
		return new JwtAuthFilter(userDetailsService, jwtUtil);
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
		return config.getAuthenticationManager();
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtAuthFilter jwtAuthFilter) throws Exception {

		http.csrf(csrf -> csrf.disable())
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.authorizeHttpRequests(auth -> auth.requestMatchers("/auth/login","/auth/refresh","/public").permitAll()
						.requestMatchers("/admin/**").hasRole("ADMIN").requestMatchers("/welcome")
						.hasAnyRole("USER", "ADMIN").anyRequest().authenticated())
				.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

		return http.build();
	}

	@Bean
	public UserDetailsService userDetailsService() {

		UserDetails user = User.builder().username(userName).password(passwordEncoder().encode(userPassword))
				.roles("USER").build();

		UserDetails admin = User.builder().username(adminName).password(passwordEncoder().encode(adminPassword))
				.roles("ADMIN").build();

		return new InMemoryUserDetailsManager(user, admin);
	}

}
