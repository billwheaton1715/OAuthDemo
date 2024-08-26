package com.siftit.domain.oauth2demo.controller;

import com.siftit.domain.oauth2demo.dto.AuthRequest;
import com.siftit.domain.oauth2demo.dto.OAuth2TokenResponse;
import com.siftit.domain.oauth2demo.service.JwtTokenProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final long jwtExpirationMs;

    // Constructor injection
    public AuthController(AuthenticationManager authenticationManager, JwtTokenProvider jwtTokenProvider,
                          @Value("${app.jwtExpirationMs}") long jwtExpirationMs) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
        this.jwtExpirationMs = jwtExpirationMs;
    }

    @PostMapping("/token")
    public ResponseEntity<?> authenticateUser(@RequestBody AuthRequest authRequest) {
        String username = authRequest.getUsername();
        String password = authRequest.getPassword();

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Generate access token and refresh token
        String accessToken = jwtTokenProvider.generateToken(username);
        String refreshToken = jwtTokenProvider.generateRefreshToken(username);
        long expiresIn = jwtExpirationMs / 1000;

        // Create OAuth2TokenResponse
        OAuth2TokenResponse tokenResponse = new OAuth2TokenResponse(accessToken, expiresIn, refreshToken);

        return ResponseEntity.ok(tokenResponse);
    }
}
