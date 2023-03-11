package com.example.springsecurityjwt.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.example.springsecurityjwt.filters.JWTRequestFilter;
import com.example.springsecurityjwt.serviceimpl.MyUserDetailsServiceImpl;
import static org.springframework.boot.autoconfigure.security.servlet.PathRequest.toH2Console;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Autowired
	private MyUserDetailsServiceImpl myUserDetailsService;

	@Autowired
	private JWTRequestFilter jwtRequestFilter;

	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(myUserDetailsService);
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http.csrf().disable().authorizeHttpRequests((authorize) -> {
			try {
				authorize.requestMatchers("/authenticate", "/swagger-ui/**", "/v3/api-docs/**").permitAll()
						.requestMatchers(toH2Console()).permitAll()
						.anyRequest().authenticated().and()
						.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
			} catch (Exception e) {
				throw new RuntimeException(e);
			}
		});

		http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class).headers().frameOptions().disable();
		return http.build();
	}

	@Bean
	public AuthenticationManager authenticationManagerBean(AuthenticationConfiguration authenticationConfiguration)
			throws Exception {
		return authenticationConfiguration.getAuthenticationManager();
	}

//	@Bean
//	public void configure(WebSecurity web) throws Exception {
//		web.ignoring().requestMatchers("/h2-console/**");
//	}

}
