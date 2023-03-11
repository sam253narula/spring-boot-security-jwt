# Spring Boot + Spring Security + JWT from scratch
- How to JWT authorization in Spring Security from scratch
- authentication api endpoint
- examine every incoming request for valid JWT and authorize

### Create App and add Security Config
This is the new set up the WebSecurityConfigurer is now deprecated
https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter

```java

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private MyUserDetailsService myUserDetailsService;

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(myUserDetailsService);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
}

```
The configureGlobal function is used because I have added @AutoWired. It then refers to the MyUserDetailsService annotated
 with @Service:

```java
@Service
public class MyUserDetailsService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return new User("foo", "foo", Collections.emptyList());
    }
}
```
This implements the Spring UserDetailsService and returns a dummy user for testing. We would use a database connection to
load the user in a real application. We have also added a JWTUtil class with functions to generate and authenticate the jwt token:
```java


@Service
public class JWTUtil {
    //...
    private String createToken(Map<String, Object> claims, String subject) {
        return Jwts.builder().setClaims(claims).setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
                .signWith(SignatureAlgorithm.ES256, SECRET_KEY).compact();
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        String username = extractUsername(token);

        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

}
```

# Next steps
### Step 1.
We now add a /authenticate API endpoint:
- accepts user ID and password
- returns JWT as response
First create authenticate endpoint to which we post the username and password. This then returns the jwt in the payload.
The client then uses the jwt in future requests as part of the header of requests to the server.

```java

package io.javabrains.springsecurityjwt;

import io.javabrains.springsecurityjwt.models.AuthenticationRequest;
import io.javabrains.springsecurityjwt.models.AuthenticationResponse;
import io.javabrains.springsecurityjwt.models.MyUser;
import io.javabrains.springsecurityjwt.repository.UserRepository;
import io.javabrains.springsecurityjwt.util.JWTUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;

@RestController
public class HelloResource {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private MyUserDetailsService userDetailsService;

    @Autowired
    UserRepository userRepository;

    @Autowired
    private JWTUtil jwtTokenUtil;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @RequestMapping({"/hello"})
    public String hello() {
        return "Hello World";
    }

    @RequestMapping(value = "/authenticate", method = RequestMethod.POST)
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception {
        userRepository.save(new MyUser("foo", "foo"));
        try {

            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword(), Collections.emptyList())
            );
        } catch (BadCredentialsException e) {
            throw new Exception("Incorrect username or password", e);
        }

        UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getUsername());

        String jwt = jwtTokenUtil.generateToken(userDetails);

        return ResponseEntity.ok(new AuthenticationResponse(jwt));
    }
}

```

We now receive a JWT token in our response from our post request to http://localhost:8081/authenticate:

![image](https://user-images.githubusercontent.com/27693622/224284554-af73d736-6e3d-451d-a624-addae1a85de2.png)

The authentication has succeeded created a JWT token and returned the token in our response. The client should then hold
onto the response and then make further requests to our API using the JWT:
![image](https://user-images.githubusercontent.com/27693622/224285884-4f10c291-2e94-42be-9e28-a20536500226.png)

This doesn't work yet because we need to set up JWT support. We need to tell Spring security to listen to every request extract
the username from the JWT and put this into the security context.

### Step 2
Intercept all incoming requests
- Extract JWT from the header
- Validate and set in execution context

To do this we need to create a filter which will take in the request, response and FilterChain to examine the incoming
request for the JWT and header and check if it is valid. It will then get the user details and save it in the security
context.

```java
package io.javabrains.springsecurityjwt.filters;

import io.javabrains.springsecurityjwt.MyUserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import io.javabrains.springsecurityjwt.util.JWTUtil;

import java.io.IOException;

@Component
public class JWTRequestFilter extends OncePerRequestFilter {
    
    @Autowired
    private MyUserDetailsService userDetailsService;
    
    @Autowired
    private JWTUtil jwtUtil;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authorizationHeader = request.getHeader("Authorization");
        
        String username = null;
        String jwt = null;
        
        
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            jwt = authorizationHeader.substring(7);
            username = jwtUtil.extractUsername(jwt);
        }
        
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
            
            if (jwtUtil.validateToken(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                
                usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }
        }
        
        filterChain.doFilter(request, response);
    }
}

```
Here we simulate adding to the context only if the JWT is present. The function then passes to the next filter in the filter chain.
We now need to tell the SecurityConfig to allow the session to be created by the JWT.

```java

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private MyUserDetailsService myUserDetailsService;

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
        http.csrf().disable()
                .authorizeHttpRequests((authorize) ->
                        {
                            try {
                                authorize
                                        .requestMatchers("/authenticate")
                                        .permitAll()
                                        .anyRequest()
                                        .authenticated()
                                        .and().sessionManagement()
                                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                            } catch (Exception e) {
                                throw new RuntimeException(e);
                            }
                        }
                );
        
        http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }


    @Bean
    public AuthenticationManager authenticationManagerBean(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

}

```
Here we make the SessionCreationPolicy stateless and add the jwtRequestFilter before the username password filter class.
We are now able to request the JWT token:

![image](https://user-images.githubusercontent.com/27693622/224290197-772aca6e-8556-4f99-bc49-10ea692e6d04.png)

and then when we use the JWT token in our request to /hello:


![image](https://user-images.githubusercontent.com/27693622/224290349-03826e7f-2bbe-4ad0-9ac5-645da9e4f5cc.png)

We receive an authenticated hello response with the http code 200.

Added swaggerdoc open api with
```pom.xml
		<dependency>
			<groupId>org.springdoc</groupId>
			<artifactId>springdoc-openapi-starter-webmvc-ui</artifactId>
			<version>2.0.2</version>
		</dependency>
```

Add OpenAPI30Configuration:
```java
@Configuration
@SecurityScheme(
        name = "bearerAuth",
        type = SecuritySchemeType.HTTP,
        bearerFormat = "JWT",
        scheme = "bearer"
)
public class OpenAPI30Configuration {
}
```

Refer to the OpenAPI30Configuration annotation in the HelloController:
```java
@RestController
//@SecurityRequirement(name = "bearerAuth")
public class HelloController {

    @GetMapping("/hello")
    @Operation(summary = "My endpoint", security = @SecurityRequirement(name = "bearerAuth"))
    public String hello() {
        return "Hello World";
    }
}

```

Add swagger endpoint to Security config:
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private MyUserDetailsService myUserDetailsService;

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
        http.csrf().disable()
                .authorizeHttpRequests((authorize) ->
                        {
                            try {
                                authorize
                                        .requestMatchers("/authenticate", "/swagger-ui/**", "/v3/api-docs/**")
                                        .permitAll()
                                        .anyRequest()
                                        .authenticated()
                                        .and().sessionManagement()
                                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                            } catch (Exception e) {
                                throw new RuntimeException(e);
                            }
                        }
                );

        http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }


    @Bean
    public AuthenticationManager authenticationManagerBean(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

}
```
Go to swagger url (http://localhost:8081/swagger-ui/index.html). Make post request for token:
![image](https://user-images.githubusercontent.com/27693622/224477752-db5ad448-a6da-4047-9e78-cc641588b80e.png)

![image](https://user-images.githubusercontent.com/27693622/224477868-52248c6d-284b-4074-acb8-47b969800964.png)


Add JWT as bearer auth by pressing the padlock on right side:
![image](https://user-images.githubusercontent.com/27693622/224477932-b49d7916-f66c-4444-afc4-d02b22c5e194.png)
We then have 200 response from the get request.


