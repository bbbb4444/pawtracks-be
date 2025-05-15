package org.example.pawtracksbe.controller;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.example.pawtracksbe.dto.CreateUserRequestDto;
import org.example.pawtracksbe.dto.LoginRequestDto;
import org.example.pawtracksbe.dto.UserResponseDto;
import org.example.pawtracksbe.security.JwtService;
import org.example.pawtracksbe.service.AppUserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final AppUserService appUserService;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    @Autowired
    public AuthController(AppUserService appUserService,
                          AuthenticationManager authenticationManager,
                          JwtService jwtService) {
        this.appUserService = appUserService;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
    }

    // JWT
    @Value("${app.jwt.cookie.name}")
    private String jwtCookieName;

    @Value("${app.jwt.cookie.secure}")
    private boolean jwtCookieSecure;

    @Value("${app.jwt.cookie.httpOnly}")
    private boolean jwtCookieHttpOnly;

    @Value("${app.jwt.cookie.sameSite}")
    private String jwtCookieSameSite;


    // CSRF
    @Value("${app.csrf.cookie.name}")
    private String csrfCookieName;

    @Value("${app.csrf.cookie.httpOnly}")
    private boolean csrfCookieHttpOnly;

    @Value("${app.csrf.cookie.secure}")
    private boolean csrfCookieSecure;

    @Value("${app.csrf.cookie.path}")
    private String csrfCookiePath;

    @Value("${app.csrf.cookie.sameSite}")
    private String csrfCookieSameSite;


    @GetMapping("/csrf")
    public ResponseEntity<?> getCsrfToken(CsrfToken token) { // Inject CsrfToken directly
        if (token != null) {
            // By injecting CsrfToken, Spring ensures it's generated/loaded.
            // The CookieCsrfTokenRepository should then ensure it's set in the response cookie.
            log.info("CSRF Token in /api/auth/csrf endpoint (via injection): HeaderName=[{}], ParameterName=[{}], TokenValue=[{}]",
                    token.getHeaderName(), token.getParameterName(), token.getToken());
        } else {
            // This case should be rare if CSRF is properly configured.
            log.warn("/api/auth/csrf endpoint: CsrfToken (via injection) was null. Check CSRF configuration.");
        }
        return ResponseEntity.ok().body("{\"message\": \"CSRF token endpoint reached, token should be in cookie if generated\"}");
    }

    /**
     * Endpoint for user registration.
     * Uses the existing AppUserService to create a new user.
     *
     * @param createUserRequestDto DTO containing user registration details.
     * @return ResponseEntity containing the created user details or an error.
     */
    @PostMapping("/register")
    public ResponseEntity<UserResponseDto> registerUser(@Valid @RequestBody CreateUserRequestDto createUserRequestDto) {
        try {
            log.info("Attempting registration for username: {}", createUserRequestDto.getUsername());
            UserResponseDto createdUser = appUserService.createUser(createUserRequestDto);
            log.info("Registration successful for username: {}", createUserRequestDto.getUsername());
            return new ResponseEntity<>(createdUser, HttpStatus.CREATED);
        } catch (IllegalArgumentException e) {
            log.warn("Registration failed: {}", e.getMessage());
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        } catch (Exception e) {
            log.error("Unexpected error during registration for username: {}", createUserRequestDto.getUsername(), e);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred during registration.", e);
        }
    }

    /**
     * Endpoint for user login.
     * Authenticates the user and returns a JWT if successful.
     *
     * @param loginRequestDto DTO containing login credentials.
     * @return ResponseEntity containing the JWT or an error.
     */
    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@Valid @RequestBody LoginRequestDto loginRequestDto,
                                       HttpServletRequest request, // Added HttpServletRequest
                                       HttpServletResponse response) {
        // Log all incoming headers for debugging CSRF
        Map<String, String> headers = new HashMap<>();
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            headers.put(headerName, request.getHeader(headerName));
        }
        log.info("Login request received for username: {}. Headers: {}", loginRequestDto.getUsername(), headers);
        String receivedCsrfToken = request.getHeader("X-XSRF-TOKEN"); // Default header name
        log.info("Received X-XSRF-TOKEN header value: [{}]", receivedCsrfToken);


        log.info("Attempting login for username: {}", loginRequestDto.getUsername());
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequestDto.getUsername(),
                            loginRequestDto.getPassword()
                    )
            );

            if (authentication.isAuthenticated()) {
                UserDetails userDetails = (UserDetails) authentication.getPrincipal();
                String token = jwtService.generateToken(userDetails);

                Cookie jwtTokenCookie = new Cookie(jwtCookieName, token);
                jwtTokenCookie.setHttpOnly(jwtCookieHttpOnly);
                jwtTokenCookie.setSecure(jwtCookieSecure);
                jwtTokenCookie.setPath("/");
                jwtTokenCookie.setMaxAge((int) (jwtService.getJwtExpirationMs() / 1000));
                if (jwtCookieSameSite != null && !jwtCookieSameSite.isBlank()) {
                    jwtTokenCookie.setAttribute("SameSite", jwtCookieSameSite);
                }
                response.addCookie(jwtTokenCookie);

                log.info("Login successful, JWT cookie set for username: {}", loginRequestDto.getUsername());
                return ResponseEntity.ok().body("{\"message\": \"Login successful\"}");
            } else {
                log.warn("Authentication failed for username: {} (not authenticated after manager call)", loginRequestDto.getUsername());
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("{\"error\": \"Authentication failed\"}");
            }

        } catch (BadCredentialsException e) {
            log.warn("Login failed for username: {} - Invalid credentials", loginRequestDto.getUsername());
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid username or password", e);
        } catch (Exception e) {
            // Important: Catching general Exception can hide CSRF AccessDeniedException if not handled by Spring Security first
            // The 403 you are seeing is likely Spring Security's CsrfFilter acting *before* this controller method is fully executed.
            // However, if it were another exception, this log would catch it.
            log.error("Error during login for username: {}", loginRequestDto.getUsername(), e);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "An error occurred during login.", e);
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logoutUser(HttpServletResponse response) {
        log.info("Attempting logout");
        Cookie jwtTokenCookie = new Cookie(jwtCookieName, null); // Clear JWT cookie
        jwtTokenCookie.setHttpOnly(jwtCookieHttpOnly);
        jwtTokenCookie.setSecure(jwtCookieSecure);
        jwtTokenCookie.setPath("/");
        jwtTokenCookie.setMaxAge(0);
        if (jwtCookieSameSite != null && !jwtCookieSameSite.isBlank()) {
            jwtTokenCookie.setAttribute("SameSite", jwtCookieSameSite);
        }
        response.addCookie(jwtTokenCookie);

        // Also clear the CSRF token cookie
        Cookie csrfTokenCookie = new Cookie(csrfCookieName, null); // Use injected csrfCookieName
        csrfTokenCookie.setHttpOnly(csrfCookieHttpOnly); // Use injected csrfCookieHttpOnly
        csrfTokenCookie.setSecure(csrfCookieSecure);   // Use injected csrfCookieSecure
        csrfTokenCookie.setPath(csrfCookiePath);       // Use injected csrfCookiePath
        csrfTokenCookie.setMaxAge(0);
        if (this.csrfCookieSameSite != null && !this.csrfCookieSameSite.isBlank()) { // Use this.csrfCookieSameSite
            csrfTokenCookie.setAttribute("SameSite", this.csrfCookieSameSite);
        }
        response.addCookie(csrfTokenCookie);


        log.info("Logout successful, JWT and CSRF cookies cleared.");
        return ResponseEntity.ok().body("{\"message\": \"Logout successful\"}");
    }

    @GetMapping("/status")
    public ResponseEntity<?> getAuthStatus(Authentication authentication) {
        if (authentication != null && authentication.isAuthenticated()) {
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            Map<String, Object> userInfo = new HashMap<>();
            userInfo.put("username", userDetails.getUsername());
            userInfo.put("authorities", userDetails.getAuthorities());
            return ResponseEntity.ok(userInfo);
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("{\"message\": \"Not authenticated\"}");
    }
}
