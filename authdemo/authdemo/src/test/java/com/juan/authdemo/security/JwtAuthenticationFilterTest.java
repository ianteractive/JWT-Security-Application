
package com.juan.authdemo.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;

import java.io.IOException;

import static org.mockito.Mockito.*;

@ExtendWith(org.mockito.junit.jupiter.MockitoExtension.class)
class JwtAuthenticationFilterTest {

    private JwtService jwtService;
    private CustomUserDetailsService userDetailsService;
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private FilterChain filterChain;

    @BeforeEach
    void setUp() {
        jwtService = mock(JwtService.class);
        userDetailsService = mock(CustomUserDetailsService.class);

        jwtAuthenticationFilter =
                new JwtAuthenticationFilter(
                        jwtService,
                        userDetailsService
                );

        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        filterChain = mock(FilterChain.class);

        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void cleanUp() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void shouldContinueFilterChainWhenAuthorizationHeaderIsMissing()
            throws ServletException, IOException {

        // Act
        jwtAuthenticationFilter.doFilter(
                request, response, filterChain
        );

        // Assert
        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(jwtService, userDetailsService);
        assertNull(
                SecurityContextHolder.getContext().getAuthentication()
        );
    }

    @Test
    void shouldAuthenticateUserWhenTokenIsValid()
            throws ServletException, IOException {

        // Arrange
        UserDetails testUser = User.withUsername("testuser")
                .password("test-password")
                .authorities(new SimpleGrantedAuthority("ROLE_USER"))
                .build();

        request.addHeader("Authorization", "Bearer valid-test-token");

        when(jwtService.extractUsername("valid-test-token"))
                .thenReturn("testuser");

        when(userDetailsService.loadUserByUsername("testuser"))
                .thenReturn(testUser);

        when(jwtService.isTokenValid("valid-test-token", testUser))
                .thenReturn(true);

        // Act
        jwtAuthenticationFilter.doFilter(
                request, response, filterChain
        );

        // Assert
        assertEquals(
                "testuser",
                SecurityContextHolder.getContext()
                        .getAuthentication()
                        .getName()
        );

        assertTrue(
                SecurityContextHolder.getContext()
                        .getAuthentication()
                        .isAuthenticated()
        );

        verify(filterChain).doFilter(request, response);
    }
    /* void shouldAuthenticateUserWhenTokenIsValid()
    Create testUser: Simulates the user returned by your user-details service.
    Add the Bearer header: Simulates a request containing a JWT.
    Mock extractUsername(): Pretends the token contains the username testuser.
    Mock loadUserByUsername(): Returns the simulated user.
    Mock isTokenValid(): Tells the filter that the token is valid.
    Run the filter: Exercises your actual JwtAuthenticationFilter code.
    Check the SecurityContext: Confirms Spring Security now recognizes testuser as authenticated.
    */


    @Test
    void shouldNotAuthenticateUserWhenTokenIsInvalid()
            throws ServletException, IOException {

        // Arrange
        request.addHeader("Authorization", "Bearer invalid-test-token");

        when(jwtService.extractUsername("invalid-test-token"))
                .thenThrow(
                        new io.jsonwebtoken.MalformedJwtException(
                                "Invalid token"
                        )
                );

        // Act
        jwtAuthenticationFilter.doFilter(
                request, response, filterChain
        );

        // Assert
        assertNull(
                SecurityContextHolder.getContext()
                        .getAuthentication()
        );

        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(userDetailsService);
    }


    @Test
    void shouldNotAuthenticateWhenUserDoesNotExist()
            throws ServletException, IOException {

        // Arrange
        request.addHeader("Authorization", "Bearer valid-test-token");

        when(jwtService.extractUsername("valid-test-token"))
                .thenReturn("missinguser");

        when(userDetailsService.loadUserByUsername("missinguser"))
                .thenThrow(
                        new org.springframework.security.core.userdetails
                                .UsernameNotFoundException("User not found")
                );

        // Act
        jwtAuthenticationFilter.doFilter(
                request, response, filterChain
        );

        // Assert
        assertNull(
                SecurityContextHolder.getContext()
                        .getAuthentication()
        );

        verify(filterChain).doFilter(request, response);
    }


    @Test
    void shouldNotAuthenticateWhenTokenValidationFails()
            throws ServletException, IOException {

        // Arrange
        UserDetails testUser = User.withUsername("testuser")
                .password("test-password")
                .roles("USER")
                .build();

        request.addHeader("Authorization", "Bearer valid-test-token");

        when(jwtService.extractUsername("valid-test-token"))
                .thenReturn("testuser");

        when(userDetailsService.loadUserByUsername("testuser"))
                .thenReturn(testUser);

        when(jwtService.isTokenValid("valid-test-token", testUser))
                .thenReturn(false);

        // Act
        jwtAuthenticationFilter.doFilter(
                request, response, filterChain
        );

        // Assert
        assertNull(
                SecurityContextHolder.getContext()
                        .getAuthentication()
        );

        verify(filterChain).doFilter(request, response);
    }


    @Test
    void shouldPreserveExistingAuthentication()
            throws ServletException, IOException {

        // Arrange
        UserDetails existingUser = User.withUsername("existinguser")
                .password("test-password")
                .roles("USER")
                .build();

        UsernamePasswordAuthenticationToken existingAuthentication =
                new UsernamePasswordAuthenticationToken(
                        existingUser,
                        null,
                        existingUser.getAuthorities()
                );

        SecurityContextHolder.getContext()
                .setAuthentication(existingAuthentication);

        request.addHeader("Authorization", "Bearer valid-test-token");

        when(jwtService.extractUsername("valid-test-token"))
                .thenReturn("testuser");

        // Act
        jwtAuthenticationFilter.doFilter(
                request, response, filterChain
        );

        // Assert
        assertSame(
                existingAuthentication,
                SecurityContextHolder.getContext().getAuthentication()
        );

        verify(jwtService).extractUsername("valid-test-token");
        verifyNoInteractions(userDetailsService);
        verify(filterChain).doFilter(request, response);
    }



}
