package org.example.pawtracksbe.security;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Value("${app.jwt.cookie.name}")
    private String jwtCookieName;

    public JwtAuthenticationFilter(final JwtService jwtService, final UserDetailsService userDetailsService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        String jwt = null;
        final String userSubject;

        // 1. Try to extract JWT from HTTP Cookie first
        if (request.getCookies() != null) {
            jwt = Arrays.stream(request.getCookies())
                    .filter(cookie -> jwtCookieName.equals(cookie.getName()))
                    .map(Cookie::getValue)
                    .findFirst()
                    .orElse(null);
            if (jwt != null) {
                log.trace("JWT extracted from cookie '{}'", jwtCookieName);
            }
        }

        // 2. If not found in cookie, try to extract from Authorization header (optional fallback)
        //    For a purely cookie-based web app, you might remove this header check eventually.
        if (jwt == null || jwt.isBlank()) {
            final String authHeader = request.getHeader("Authorization");
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                jwt = authHeader.substring(7);
                log.trace("JWT extracted from Authorization header (cookie was not found or empty)");
            }
        }

        // If JWT is still null or blank after checking both cookie and header, pass to the next filter
        if (jwt == null || jwt.isBlank()) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            // 3. Extract the user identifier (subject) from the token using JwtService
            userSubject = jwtService.extractUsername(jwt);

            // 4. Check if subject exists and if user is not already authenticated
            if (userSubject != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                // Load UserDetails from the database via UserDetailsService
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(userSubject);

                // 5. Validate the token (checks signature, expiration, and if subject matches UserDetails)
                if (jwtService.isTokenValid(jwt, userDetails)) {
                    // If token is valid, create an Authentication object
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails,        // Principal (the user)
                            null,               // Credentials (not needed for JWT auth with cookies/bearer)
                            userDetails.getAuthorities() // User's roles/permissions
                    );

                    // Set additional details about the authentication request
                    authToken.setDetails(
                            new WebAuthenticationDetailsSource().buildDetails(request)
                    );

                    // 6. Update the SecurityContextHolder with the new authentication token
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                    log.debug("User '{}' authenticated successfully via JWT.", userSubject);
                } else {
                    log.warn("JWT token validation failed for user: {}", userSubject);
                }
            }
        } catch (ExpiredJwtException e) {
            log.warn("JWT token is expired: {}", e.getMessage());
            // Consider how you want to handle expired tokens.
            // For an API, usually, you just let it proceed, and the lack of authentication
            // will result in a 401/403 further down the chain if the endpoint is protected.
            // Or, you could explicitly send a 401 here.
        } catch (UnsupportedJwtException e) {
            log.warn("JWT token is unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            log.warn("JWT token is malformed: {}", e.getMessage());
        } catch (SignatureException e) {
            log.warn("JWT signature validation failed: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.warn("JWT claims string is empty, null, or invalid: {}", e.getMessage());
        } catch (Exception e) {
            log.error("Could not set user authentication in security context for request to {}: {}", request.getRequestURI(), e.getMessage(), e);
        }

        filterChain.doFilter(request, response);
    }
}