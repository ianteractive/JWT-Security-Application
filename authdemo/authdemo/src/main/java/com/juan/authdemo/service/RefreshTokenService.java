
package com.juan.authdemo.service;

import com.juan.authdemo.dto.AuthResponse;
import com.juan.authdemo.entity.RefreshToken;
import com.juan.authdemo.entity.User;
import com.juan.authdemo.repository.RefreshTokenRepository;
import com.juan.authdemo.security.JwtService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final SecureRandom secureRandom = new SecureRandom();
    private final long refreshTokenExpiration;
    private final JwtService jwtService;


    public RefreshTokenService(
            RefreshTokenRepository refreshTokenRepository,
            @Value("${jwt.refresh-expiration:604800000}") long refreshTokenExpiration, JwtService jwtService) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.refreshTokenExpiration = refreshTokenExpiration;
        this.jwtService = jwtService;
    }

    @Transactional
    public String createRefreshToken(User user) {
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);

        String rawToken = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(randomBytes);

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setTokenHash(hashToken(rawToken));
        refreshToken.setUser(user);
        refreshToken.setExpiresAt(
                Instant.now().plusMillis(refreshTokenExpiration));
        refreshToken.setRevoked(false);

        refreshTokenRepository.save(refreshToken);

        return rawToken;
    }

    public String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(
                    token.getBytes(StandardCharsets.UTF_8));

            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(
                    "SHA-256 is not available", exception);
        }
    }


    @Transactional
    public AuthResponse refreshAccessToken(String rawToken) {

        String tokenHash = hashToken(rawToken);

        RefreshToken storedToken = refreshTokenRepository
                .findByTokenHash(tokenHash)
                .orElseThrow(() ->
                        new IllegalArgumentException("Invalid refresh token"));

        if (storedToken.isRevoked()) {
            throw new IllegalArgumentException("Refresh token has been revoked");
        }

        if (!storedToken.getExpiresAt().isAfter(Instant.now())) {
            throw new IllegalArgumentException("Refresh token has expired");
        }

        User user = storedToken.getUser();

        UserDetails userDetails =
                org.springframework.security.core.userdetails.User
                        .withUsername(user.getUsername())
                        .password(user.getPassword())
                        .roles(user.getRole())
                        .build();

        // Rotate: invalidate the old refresh token.
        storedToken.setRevoked(true);
        refreshTokenRepository.save(storedToken);

        // Generate a new refresh token for this user.
        String newRefreshToken = createRefreshToken(user);

        // Generate a new access token.
        String newAccessToken = jwtService.generateToken(userDetails);

        return new AuthResponse(
                newAccessToken,
                newRefreshToken,
                "Bearer"
        );
    }


    @Transactional
    public void logout(String rawToken) {

        if (rawToken == null || rawToken.isBlank()) {
            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "Invalid refresh token"
            );
        }

        RefreshToken storedToken = refreshTokenRepository
                .findByTokenHash(hashToken(rawToken))
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED,
                        "Invalid refresh token"
                ));

        if (storedToken.isRevoked()
                || !storedToken.getExpiresAt().isAfter(Instant.now())) {
            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "Invalid refresh token"
            );
        }

        storedToken.setRevoked(true);
        refreshTokenRepository.save(storedToken);
    }

}
