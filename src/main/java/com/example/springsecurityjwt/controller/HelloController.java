package com.example.springsecurityjwt.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
//@SecurityRequirement(name = "bearerAuth")
public class HelloController {

    @GetMapping("/hello")
    @Operation(summary = "My endpoint", security = @SecurityRequirement(name = "bearerAuth"))
    public String hello() {
        return "Hello World";
    }
}
