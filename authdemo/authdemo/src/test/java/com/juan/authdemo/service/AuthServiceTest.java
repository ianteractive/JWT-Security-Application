
package com.juan.authdemo.service;

import com.juan.authdemo.dto.AuthResponse;
import com.juan.authdemo.dto.LoginRequest;
import com.juan.authdemo.dto.RegisterRequest;
import com.juan.authdemo.entity.User;
import com.juan.authdemo.repository.UserRepository;
import com.juan.authdemo.security.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AuthServiceTest {

    private UserRepository userRepository;
    private PasswordEncoder passwordEncoder;
    private AuthenticationManager authenticationManager;
    private JwtService jwtService;
    private RefreshTokenService refreshTokenService;

    private AuthService authService;

    @BeforeEach
    void setUp() {
        userRepository = mock(UserRepository.class);
        passwordEncoder = mock(PasswordEncoder.class);
        authenticationManager = mock(AuthenticationManager.class);
        jwtService = mock(JwtService.class);

        authService = new AuthService(
                userRepository,
                passwordEncoder,
                authenticationManager,
                jwtService,
                refreshTokenService
        );
    }

    @Test
    void shouldRegisterUserSuccessfully() {
        // Arrange
        RegisterRequest request = new RegisterRequest();
        request.setUsername("testuser");
        request.setPassword("plain-password");

        when(userRepository.existsByUsername("testuser"))
                .thenReturn(false);

        when(passwordEncoder.encode("plain-password"))
                .thenReturn("encoded-password");

        // Act
        authService.register(request);

        // Assert
        verify(userRepository).existsByUsername("testuser");

        verify(passwordEncoder).encode("plain-password");

        verify(userRepository).save(argThat(user ->
                user.getUsername().equals("testuser")
                        && user.getPassword().equals("encoded-password")
                        && user.getRole().equals("USER")
        ));
    }

    @Test
    void shouldRejectDuplicateUsername() {
        // Arrange
        RegisterRequest request = new RegisterRequest();
        request.setUsername("testuser");
        request.setPassword("plain-password");

        when(userRepository.existsByUsername("testuser"))
                .thenReturn(true);

        // Act & Assert
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> authService.register(request)
        );

        assertEquals("User already exists", exception.getMessage());

        verify(userRepository).existsByUsername("testuser");

        verify(userRepository, never()).save(any(User.class));

        verifyNoInteractions(passwordEncoder);
    }


    @Test
    void shouldLoginSuccessfullyAndReturnToken() {
        // Arrange
        LoginRequest request = new LoginRequest();
        request.setUsername("testuser");
        request.setPassword("plain-password");

        UserDetails userDetails = org.springframework.security.core.userdetails.User.withUsername("testuser")
                .password("encoded-password")
                .roles("USER")
                .build();

        Authentication authentication =
                new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );

        when(authenticationManager.authenticate(any(
                UsernamePasswordAuthenticationToken.class
        ))).thenReturn(authentication);

        when(jwtService.generateToken(userDetails))
                .thenReturn("mock-jwt-token");

        // Act
        AuthResponse response = authService.login(request);

        // Assert
        assertEquals("mock-jwt-token", response.getToken());
        assertEquals("Bearer", response.getTokenType());

        verify(authenticationManager).authenticate(any(
                UsernamePasswordAuthenticationToken.class
        ));

        verify(jwtService).generateToken(userDetails);
    }


    @Test
    void shouldRejectLoginWhenAuthenticationFails() {
        // Arrange
        LoginRequest request = new LoginRequest();
        request.setUsername("testuser");
        request.setPassword("wrong-password");

        when(authenticationManager.authenticate(any(
                UsernamePasswordAuthenticationToken.class
        ))).thenThrow(
                new org.springframework.security.authentication.BadCredentialsException(
                        "Invalid username or password"
                )
        );

        // Act & Assert
        assertThrows(
                org.springframework.security.authentication.BadCredentialsException.class,
                () -> authService.login(request)
        );

        verify(authenticationManager).authenticate(any(
                UsernamePasswordAuthenticationToken.class
        ));

        verifyNoInteractions(jwtService);
    }


    @Test
    void shouldAuthenticateUsingSubmittedCredentials() {
        // Arrange
        LoginRequest request = new LoginRequest();
        request.setUsername("testuser");
        request.setPassword("plain-password");

        when(authenticationManager.authenticate(any(
                UsernamePasswordAuthenticationToken.class
        ))).thenThrow(
                new org.springframework.security.authentication.BadCredentialsException(
                        "Invalid username or password"
                )
        );

        // Act
        assertThrows(
                org.springframework.security.authentication.BadCredentialsException.class,
                () -> authService.login(request)
        );

        // Assert
        org.mockito.ArgumentCaptor<UsernamePasswordAuthenticationToken> captor =
                org.mockito.ArgumentCaptor.forClass(
                        UsernamePasswordAuthenticationToken.class
                );

        verify(authenticationManager).authenticate(captor.capture());

        UsernamePasswordAuthenticationToken submittedToken = captor.getValue();

        assertEquals("testuser", submittedToken.getPrincipal());
        assertEquals("plain-password", submittedToken.getCredentials());
    }

}
