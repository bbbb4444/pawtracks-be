package org.example.pawtracksbe.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
public class JwtService {

    private static final Logger log = LoggerFactory.getLogger(JwtService.class);

    private final String secretKeyString;
    @Getter
    private final long jwtExpirationMs;
    private SecretKey jwtSigningKey;
    private JwtParser jwtParser;

    public JwtService(
            @Value("${jwt.secret-key}") String secretKeyString,
            @Value("${jwt.expiration-ms}") long jwtExpirationMs) {
        this.secretKeyString = secretKeyString;
        this.jwtExpirationMs = jwtExpirationMs;
    }

    @PostConstruct
    public void init() {
        if (secretKeyString == null || secretKeyString.isBlank()) {
            log.error("FATAL: jwt.secret-key property is missing or empty!");
            throw new IllegalArgumentException("jwt.secret-key property must be set");
        }

        byte[] keyBytes;
        try {
            keyBytes = Decoders.BASE64.decode(secretKeyString);
        } catch (IllegalArgumentException e) {
            log.error("FATAL: jwt.secret-key is not valid Base64 encoded!", e);
            throw new IllegalArgumentException("jwt.secret-key must be Base64 encoded");
        }

        if (keyBytes.length < 64) {
            log.error("FATAL: jwt.secret-key must be at least 64 bytes long for HS512 after Base64 decoding (was {} bytes)!", keyBytes.length);
            throw new IllegalArgumentException("jwt.secret-key must be at least 64 bytes for HS512");
        }

        this.jwtSigningKey = Keys.hmacShaKeyFor(keyBytes);
        this.jwtParser = Jwts.parser().verifyWith(this.jwtSigningKey).build();
        log.info("JwtService initialized successfully with HS512 algorithm.");
        log.info("JWT expiration time set to {} ms", jwtExpirationMs);
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        String roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
        claims.put("roles", roles);
        log.debug("Generating token for user: {}, roles: {}", userDetails.getUsername(), roles);
        return buildToken(claims, userDetails, jwtExpirationMs);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        log.debug("Generating token with extra claims for user: {}", userDetails.getUsername());
        return buildToken(extraClaims, userDetails, jwtExpirationMs);
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        try {
            final String username = extractUsername(token);
            boolean usernameMatches = username.equals(userDetails.getUsername());
            if (!usernameMatches) {
                log.warn("Token subject '{}' does not match UserDetails username '{}'", username, userDetails.getUsername());
                return false;
            }
            log.trace("Token validation successful for user {}", username);
            return true;
        } catch (MalformedJwtException e) {
            log.warn("Invalid JWT token format: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            log.warn("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.warn("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.warn("JWT claims string is empty or invalid: {}", e.getMessage());
        } catch (SignatureException e) {
            log.warn("JWT signature validation failed: {}", e.getMessage());
        } catch (Exception e) {
            log.error("Unexpected error during token validation for user {}", userDetails.getUsername(), e);
        }
        return false;
    }

    // --- Private Helper Methods ---

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private String buildToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            long expirationMs
    ) {
        return Jwts.builder()
                .claims(extraClaims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expirationMs))
                .signWith(getJwtSigningKey())
                .compact();
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        return jwtParser.parseSignedClaims(token).getPayload();
    }

    private SecretKey getJwtSigningKey() {
        return jwtSigningKey;
    }

    public String generateTokenExpiredMinutesAgo(UserDetails userDetails, long minutesAgo) {
        Instant now = Instant.now();
        Instant expirationInstant = now.minus(minutesAgo, ChronoUnit.MINUTES);

        Map<String, Object> claims = new HashMap<>();
        String roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
        claims.put("roles", roles);

        return Jwts.builder()
                .claims(claims)
                .subject(userDetails.getUsername())
                .issuedAt(Date.from(now))
                .expiration(Date.from(expirationInstant))
                .signWith(getJwtSigningKey())
                .compact();
    }
}