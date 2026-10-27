package com.juan.authdemo.controller;

import com.juan.authdemo.dto.AuthResponse;
import com.juan.authdemo.dto.LoginRequest;
import com.juan.authdemo.dto.RefreshTokenRequest;
import com.juan.authdemo.dto.RegisterRequest;
import com.juan.authdemo.service.AuthService;
import com.juan.authdemo.service.RefreshTokenService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;
    private final RefreshTokenService refreshTokenService;

    public AuthController(AuthService authService, RefreshTokenService refreshTokenService) {
        this.authService = authService;
        this.refreshTokenService = refreshTokenService;
    }

    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> register(
            @Valid @RequestBody RegisterRequest request){

        authService.register(request);

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(Map.of("message", "User registered successfully"));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(
            @Valid @RequestBody LoginRequest request) {

        AuthResponse response = authService.login(request);

        return ResponseEntity.ok(response);
    }


    @PostMapping("/refresh")
    public AuthResponse refresh(
            @RequestBody RefreshTokenRequest request) {

        return refreshTokenService.refreshAccessToken(
                request.getRefreshToken()
        );
    }


    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @RequestBody RefreshTokenRequest request) {

        refreshTokenService.logout(request.getRefreshToken());

        return ResponseEntity.noContent().build();
    }


}
