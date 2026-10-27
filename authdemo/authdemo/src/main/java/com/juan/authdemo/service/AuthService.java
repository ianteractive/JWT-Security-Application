package com.juan.authdemo.service;

import com.juan.authdemo.dto.AuthResponse;
import com.juan.authdemo.dto.LoginRequest;
import com.juan.authdemo.dto.RegisterRequest;
import com.juan.authdemo.entity.User;
import com.juan.authdemo.repository.UserRepository;
import com.juan.authdemo.security.JwtService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    public AuthService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            AuthenticationManager authenticationManager,
            JwtService jwtService,
            RefreshTokenService refreshTokenService) {

        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
    }

    public void register(RegisterRequest request){
        if (userRepository.existsByUsername(request.getUsername())){
            throw new IllegalArgumentException("User already exists");
        }

        User user = new User(
                request.getUsername(),
                passwordEncoder.encode(request.getPassword()),
                "USER"
                );
        userRepository.save(user);
    }

    public AuthResponse login(LoginRequest request) {

        Authentication authentication =
                authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(
                                request.getUsername(),
                                request.getPassword()
                        )
                );

        UserDetails userDetails =
                (UserDetails) authentication.getPrincipal();

        // Generate the access token
        String accessToken =
                jwtService.generateToken(userDetails);

        // Find the application User entity
        User user = userRepository
                .findByUsername(userDetails.getUsername())
                .orElseThrow(() ->
                        new IllegalArgumentException("User not found"));

        // Generate and store the refresh token
        String refreshToken =
                refreshTokenService.createRefreshToken(user);

        // Return both tokens
        return new AuthResponse(
                accessToken,
                refreshToken,
                "Bearer");
    }
}
