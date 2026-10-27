
package com.juan.authdemo.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class TestController {

    @GetMapping("/api/test/protected")
    public Map<String, String> protectedEndpoint() {
        return Map.of(
                "message",
                "You accessed a protected endpoint!"
        );
    }

    @GetMapping("/api/test/user")
    public Map<String, String> userEndpoint(
            org.springframework.security.core.Authentication authentication) {

        return Map.of(
                "message", "Welcome, " + authentication.getName() + "!",
                "role", authentication.getAuthorities().toString()
        );
    }

    @GetMapping("/api/test/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, String> adminEndpoint() {
        return Map.of(
                "message", "Welcome to the admin endpoint!"
        );
    }
}
