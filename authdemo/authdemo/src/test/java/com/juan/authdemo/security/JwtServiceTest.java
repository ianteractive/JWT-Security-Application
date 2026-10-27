package com.juan.authdemo.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Base64;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

public class JwtServiceTest {
    private JwtService jwtService;
    private UserDetails userDetails;
    private final String testSecret =
            Base64.getEncoder().encodeToString(
                    "01234567890123456789012345678901"
                            .getBytes()
            );

    @BeforeEach
    void setUp(){
        byte[] secretBytes =  "01234567890123456789012345678901".getBytes();

        jwtService = new JwtService(testSecret, 3600000);

        userDetails = User.withUsername("testuser")
                .password("test-password")
                .roles("USER")
                .build();
    }

    @Test
    void shouldGenerateTokenAndExtractUsername(){
        //Arrange
        String token = jwtService.generateToken(userDetails);

        //Act
        String username = jwtService.extractUsername(token);

        //Assert
        assertNotNull(token);
        assertFalse(token.isBlank());
        assertEquals("testuser", username);
    }

    @Test
    void shouldReturnTrueForValidToken() {
        // Arrange
        String token = jwtService.generateToken(userDetails);

        // Act
        boolean result = jwtService.isTokenValid(token, userDetails);

        // Assert
        assertTrue(result);
    }

    @Test
    void shouldReturnFalseForExpiredToken() throws InterruptedException {
        // Arrange
        JwtService shortLivedJwtService =
                new JwtService(
                        Base64.getEncoder().encodeToString(
                                "01234567890123456789012345678901".getBytes()
                        ),
                        1
                );

        String token = shortLivedJwtService.generateToken(userDetails);

        // Wait for the token to expire
        Thread.sleep(1100);

        // Act
        boolean result = shortLivedJwtService.isTokenValid(token, userDetails);

        // Assert
        assertFalse(result);
    }


    @Test
    void shouldReturnFalseForInvalidSignature() {
        // Arrange
        byte[] differentSecretBytes =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456".getBytes();

        String differentSecret =
                Base64.getEncoder().encodeToString(differentSecretBytes);

        JwtService otherJwtService =
                new JwtService(differentSecret, 3600000);

        String token = otherJwtService.generateToken(userDetails);

        // Act
        boolean result = jwtService.isTokenValid(token, userDetails);

        // Assert
        assertFalse(result);
    }


    @Test
    void shouldReturnFalseForMalformedToken() {
        // Arrange
        String malformedToken = "this-is-not-a-valid-jwt";

        // Act
        boolean result =
                jwtService.isTokenValid(malformedToken, userDetails);

        // Assert
        assertFalse(result);
    }


    @Test
    void shouldReturnFalseWhenUsernameDoesNotMatch() {
        // Arrange
        String token = jwtService.generateToken(userDetails);

        UserDetails differentUser = User.withUsername("anotheruser")
                .password("test-password")
                .roles("USER")
                .build();

        // Act
        boolean result = jwtService.isTokenValid(token, differentUser);

        // Assert
        assertFalse(result);
    }


    @Test
    void shouldRejectTokenWithWrongIssuer() {
        // Arrange
        String tokenWithWrongIssuer = Jwts.builder()
                .subject("testuser")
                .issuer("another-application")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60000))
                .signWith(
                        Keys.hmacShaKeyFor(
                                Decoders.BASE64.decode(testSecret)
                        )
                )
                .compact();

        // Act & Assert
        assertFalse(
                jwtService.isTokenValid(tokenWithWrongIssuer, userDetails)
        );
    }



}
