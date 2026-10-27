
package com.juan.authdemo.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
//OncePerRequestFilter — runs the filter once per request within the applicable filter dispatch.
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final CustomUserDetailsService userDetailsService;

    public JwtAuthenticationFilter(
            JwtService jwtService,
            CustomUserDetailsService userDetailsService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain)
            throws ServletException, IOException {

        //getHeader("Authorization") — reads the request's authorization header.
        String authorizationHeader =
                request.getHeader("Authorization");

        if (authorizationHeader == null
                || !authorizationHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        //substring(7) — removes the seven-character prefix Bearer  to get the token.
        String token = authorizationHeader.substring(7);

        try {
            String username = jwtService.extractUsername(token); //extractUsername(token) — validates and reads the signed token's subject.

            if (username != null
                    && SecurityContextHolder.getContext()
                    .getAuthentication() == null) {

                UserDetails userDetails =
                        userDetailsService.loadUserByUsername(username); //loadUserByUsername(username) — loads the current user and their authorities from your database.

                if (jwtService.isTokenValid(token, userDetails)) { //isTokenValid(...) — verifies the token is valid for that user and hasn't expired.

                    UsernamePasswordAuthenticationToken authentication =
                            new UsernamePasswordAuthenticationToken(
                                    userDetails,
                                    null,
                                    userDetails.getAuthorities()
                            );

                    authentication.setDetails(
                            new WebAuthenticationDetailsSource()
                                    .buildDetails(request)
                    );

                    SecurityContextHolder.getContext()
                            .setAuthentication(authentication); //setAuthentication(authentication) — tells Spring Security that this request is authenticated.
                }
            }
        } catch (io.jsonwebtoken.JwtException
                 | IllegalArgumentException exception) {
            // Invalid token: leave the request unauthenticated.
        } catch (org.springframework.security.core.userdetails
                         .UsernameNotFoundException exception) {
            SecurityContextHolder.clearContext();
            // The token refers to a user who no longer exists.
        }

        filterChain.doFilter(request, response);
    }
}
