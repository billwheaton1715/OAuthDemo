package com.siftit.domain.oauth2demo.service;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.core.io.Resource;

import java.nio.file.Files;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class JwtTokenProvider {

    @Value("${app.jwtExpirationMs}")
    private long jwtExpirationMs;

    @Value("${app.jwtRefreshExpirationMs}")
    private long jwtRefreshExpirationMs;

    private final PrivateKey privateKey;
    @Getter
    private final PublicKey publicKey;


    private final UserDetailsService userDetailsService;

    public JwtTokenProvider(UserDetailsService userDetailsService,
                            @Value("${jwt.privateKeyPath}") String privateKeyPath,
                            @Value("${jwt.publicKeyPath}") String publicKeyPath,
                            ResourceLoader resourceLoader) {
        this.userDetailsService = userDetailsService;
        try {
            System.out.println("Loading private key from: " + privateKeyPath);
            System.out.println("Loading public key from: " + publicKeyPath);

            this.privateKey = loadPrivateKey(resourceLoader.getResource(privateKeyPath));
            this.publicKey = loadPublicKey(resourceLoader.getResource(publicKeyPath));

            System.out.println("Keys loaded successfully");
        } catch (Exception e) {
            throw new RuntimeException("Failed to load keys", e);
        }
    }


    private PrivateKey loadPrivateKey(Resource resource) throws Exception {
        byte[] keyBytes = Files.readAllBytes(resource.getFile().toPath());
        String privateKeyContent = new String(keyBytes)
                .replaceAll("\\n", "")
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "");
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
        return keyFactory.generatePrivate(keySpec);
    }

    private PublicKey loadPublicKey(Resource resource) throws Exception {
        byte[] keyBytes = Files.readAllBytes(resource.getFile().toPath());
        String publicKeyContent = new String(keyBytes)
                .replaceAll("\\n", "")
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "");
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyContent));
        return keyFactory.generatePublic(keySpec);
    }

    public Authentication getAuthentication(String token) {
        String username = getUsernameFromJWT(token);

        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        List<SimpleGrantedAuthority> authorities = extractAuthoritiesFromToken(token);
        return new UsernamePasswordAuthenticationToken(userDetails, null, authorities);
    }

    public String generateToken(String username) {
        UserDetails userDetails = loadUserByUsername(username);
        List<String> roles = userDetails.getAuthorities().stream()
                .map(authority -> authority.getAuthority().replace("ROLE_", ""))
                .collect(Collectors.toList());

        String retval = Jwts.builder()
                .setSubject(username)
                .claim("roles", roles)
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(privateKey) // Use private key for signing
                .compact();
        System.out.println(getUsernameFromJWT(retval));
        System.out.println(extractAuthoritiesFromToken(retval));
        return retval;
    }

    public String generateRefreshToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtRefreshExpirationMs))
                .signWith(privateKey) // Use private key for signing
                .compact();
    }

    public String getUsernameFromJWT(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(token)
                .getBody();

        return claims.getSubject();
    }

    public boolean validateToken(String authToken) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(publicKey)
                    .build()
                    .parseClaimsJws(authToken);
            return true;
        } catch (Exception e) {
            System.out.println("Token validation failed: " + e.getMessage());
            return false;
        }
    }

    private UserDetails loadUserByUsername(String username) {
        try {
            return userDetailsService.loadUserByUsername(username);
        } catch (UsernameNotFoundException e) {
            throw new RuntimeException("User not found: " + username);
        }
    }

    private List<SimpleGrantedAuthority> extractAuthoritiesFromToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(token)
                .getBody();

        List<?> rawRoles = claims.get("roles", List.class);
        List<String> roles = rawRoles.stream()
                .filter(role -> role instanceof String)
                .map(Object::toString)
                .toList();

        return roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role)) // Ensure role has "ROLE_" prefix
                .collect(Collectors.toList());
    }

}
