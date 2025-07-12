package org.example.pawtracksbe.controller;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.example.pawtracksbe.dto.LoginRequestDto;
import org.example.pawtracksbe.entity.AppUser;
import org.example.pawtracksbe.entity.RefreshToken;
import org.example.pawtracksbe.repository.JwtRefreshRepository;
import org.example.pawtracksbe.security.JwtRefreshService;
import org.example.pawtracksbe.security.JwtService;
import org.example.pawtracksbe.service.AppUserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.time.Duration;
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
    private final JwtRefreshService jwtRefreshService;
    private final UserDetailsService userDetailsService;
    private final JwtRefreshRepository jwtRefreshRepository;

    @Autowired
    public AuthController(AppUserService appUserService,
                          AuthenticationManager authenticationManager,
                          JwtService jwtService,
                          JwtRefreshService jwtRefreshService, UserDetailsService userDetailsService, JwtRefreshRepository jwtRefreshRepository) {
        this.appUserService = appUserService;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.jwtRefreshService = jwtRefreshService;
        this.userDetailsService = userDetailsService;
        this.jwtRefreshRepository = jwtRefreshRepository;
    }

    @Value("${app.cookie.domain}")
    private String cookieDomain;

    // JWT
    @Value("${app.jwt.cookie.name}")
    private String jwtCookieName;

    @Value("${app.jwt.cookie.secure}")
    private boolean jwtCookieSecure;

    @Value("${app.jwt.cookie.httpOnly}")
    private boolean jwtCookieHttpOnly;

    @Value("${app.jwt.cookie.sameSite}")
    private String jwtCookieSameSite;

    // JWT Refresh
    @Value("${app.jwt.refresh.cookie.name}")
    private String jwtRefreshCookieName;

    @Value("${app.jwt.refresh.cookie.secure}")
    private boolean jwtRefreshCookieSecure;

    @Value("${app.jwt.refresh.cookie.httpOnly}")
    private boolean jwtRefreshCookieHttpOnly;

    @Value("${app.jwt.refresh.cookie.sameSite}")
    private String jwtRefreshCookieSameSite;

    @Value("${app.jwt.refresh.expiration-ms}")
    private long jwtRefreshCookieExpiration;

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
    public ResponseEntity<?> getCsrfToken(CsrfToken token) {
        if (token != null) {
            log.info("CSRF Token in /api/auth/csrf endpoint (via injection): HeaderName=[{}], ParameterName=[{}], TokenValue=[{}]",
                    token.getHeaderName(), token.getParameterName(), token.getToken());
            Map<String, String> tokenMap = new HashMap<>();
            tokenMap.put("token", token.getToken());
            tokenMap.put("headerName", token.getHeaderName());
            tokenMap.put("parameterName", token.getParameterName());
            return ResponseEntity.ok(tokenMap);
        } else {
            log.warn("/api/auth/csrf endpoint: CsrfToken (via injection) was null. Check CSRF configuration.");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("{\"error\": \"CSRF token not available from server.\"}");
        }
    }

    /**
     * Endpoint for user registration.
     * Uses the existing AppUserService to create a new user.
     *
     * @param createUserRequestDto DTO containing user registration details.
     * @return ResponseEntity containing the created user details or an error.
     */
//    @PostMapping("/register")
//    public ResponseEntity<UserResponseDto> registerUser(@Valid @RequestBody CreateUserRequestDto createUserRequestDto) {
//        try {
//            log.info("Attempting registration for username: {}", createUserRequestDto.getUsername());
//            UserResponseDto createdUser = appUserService.createUser(createUserRequestDto);
//            log.info("Registration successful for username: {}", createUserRequestDto.getUsername());
//            return new ResponseEntity<>(createdUser, HttpStatus.CREATED);
//        } catch (IllegalArgumentException e) {
//            log.warn("Registration failed: {}", e.getMessage());
//            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
//        } catch (Exception e) {
//            log.error("Unexpected error during registration for username: {}", createUserRequestDto.getUsername(), e);
//            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred during registration.", e);
//        }
//    }

    /**
     * Endpoint for user login.
     * Authenticates the user and returns a JWT if successful.
     *
     * @param loginRequestDto DTO containing login credentials.
     * @return ResponseEntity containing the JWT or an error.
     */

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@Valid @RequestBody LoginRequestDto loginRequestDto,
                                       HttpServletRequest request,
                                       HttpServletResponse response) {
        Map<String, String> headers = new HashMap<>();
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            headers.put(headerName, request.getHeader(headerName));
        }
        log.info("Login request received for username: {}. Headers: {}", loginRequestDto.getUsername(), headers);
        String receivedCsrfToken = request.getHeader("X-XSRF-TOKEN");
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

                // === Use ResponseCookie Builder for Access Token ===
                String accessToken = jwtService.generateToken(userDetails);
                ResponseCookie accessTokenCookie = ResponseCookie.from(jwtCookieName, accessToken)
                        .httpOnly(jwtCookieHttpOnly)
                        .secure(jwtCookieSecure)
                        .path("/")
                        .maxAge(Duration.ofMillis(jwtService.getJwtExpirationMs()))
                        .sameSite(jwtCookieSameSite)
                        .domain(cookieDomain)
                        .build();
                response.addHeader(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());


                // === Use ResponseCookie Builder for Refresh Token ===
                RefreshToken refreshToken = jwtRefreshService.generateRefreshToken(userDetails.getUsername());
                ResponseCookie refreshTokenCookie = ResponseCookie.from(jwtRefreshCookieName, refreshToken.getToken())
                        .httpOnly(jwtRefreshCookieHttpOnly)
                        .secure(jwtRefreshCookieSecure)
                        .path("/")
                        .maxAge(Duration.ofMillis(jwtRefreshCookieExpiration))
                        .sameSite(jwtRefreshCookieSameSite)
                        .domain(cookieDomain)
                        .build();
                response.addHeader(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());

                log.info("Login successful, JWT cookie and refresh token set for username: {}", loginRequestDto.getUsername());
                return ResponseEntity.ok().body("{\"message\": \"Login successful\"}");
            } else {
                log.warn("Authentication failed for username: {} (not authenticated after manager call)", loginRequestDto.getUsername());
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("{\"error\": \"Authentication failed\"}");
            }

        } catch (BadCredentialsException e) {
            log.warn("Login failed for username: {} - Invalid credentials", loginRequestDto.getUsername());
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid username or password", e);
        } catch (Exception e) {
            log.error("Error during login for username: {}", loginRequestDto.getUsername(), e);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "An error occurred during login.", e);
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logoutUser(HttpServletRequest request, HttpServletResponse response) {
        log.info("Attempting logout");

        // Invalidate refresh token
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (jwtRefreshCookieName.equals(cookie.getName())) {
                    String tokenValue = cookie.getValue();
                    jwtRefreshService.deleteByToken(tokenValue);
                    log.info("Refresh token invalidated from database.");
                    break;
                }
            }
        }

        // Clear all cookies by creating expired cookies with the same properties
        ResponseCookie emptyAccessTokenCookie = ResponseCookie.from(jwtCookieName, "")
                .httpOnly(jwtCookieHttpOnly)
                .secure(jwtCookieSecure)
                .path("/")
                .maxAge(0)
                .sameSite(jwtCookieSameSite)
                .domain(cookieDomain)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, emptyAccessTokenCookie.toString());

        ResponseCookie emptyRefreshTokenCookie = ResponseCookie.from(jwtRefreshCookieName, "")
                .httpOnly(jwtRefreshCookieHttpOnly)
                .secure(jwtRefreshCookieSecure)
                .path("/")
                .maxAge(0)
                .sameSite(jwtRefreshCookieSameSite)
                .domain(cookieDomain)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, emptyRefreshTokenCookie.toString());

        ResponseCookie emptyCsrfTokenCookie = ResponseCookie.from(csrfCookieName, "")
                .path(csrfCookiePath)
                .maxAge(0)
                .secure(csrfCookieSecure)
                .sameSite(csrfCookieSameSite)
                .domain(cookieDomain)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, emptyCsrfTokenCookie.toString());

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

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(HttpServletRequest request, HttpServletResponse response) {
        String requestRefreshToken = null;
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (jwtRefreshCookieName.equals(cookie.getName())) {
                    requestRefreshToken = cookie.getValue();
                    break;
                }
            }
        }

        if (requestRefreshToken == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("{\"error\": \"Refresh token is missing\"}");
        }

        UserDetails userDetails = jwtRefreshService.findByToken(requestRefreshToken)
                .map(jwtRefreshService::verifyExpiration)
                .map(RefreshToken::getUser)
                .map(AppUser::getUsername)
                .map(userDetailsService::loadUserByUsername)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Refresh token not found or invalid"));

        String newAccessToken = jwtService.generateToken(userDetails);

        ResponseCookie newAccessTokenCookie = ResponseCookie.from(jwtCookieName, newAccessToken)
                .httpOnly(jwtCookieHttpOnly)
                .secure(jwtCookieSecure)
                .path("/")
                .maxAge(Duration.ofMillis(jwtService.getJwtExpirationMs()))
                .sameSite(jwtCookieSameSite)
                .domain(cookieDomain)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, newAccessTokenCookie.toString());

        return ResponseEntity.ok().body("{\"message\": \"Access token refreshed\"}");
    }
}
