package org.example.pawtracksbe.security;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collections;
import java.util.Collection;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class JwtServiceTest {

    private static final Logger log = LoggerFactory.getLogger(JwtServiceTest.class);

    private final String testSecretKeyBase64 = "eW91clN1cGVyU2VjcmV0QW5kTG9uZ0Vub3VnaEtleUZvclRlc3RpbmdIUzUxMkFsZ29yaXRobU11c3RCZUF0TGVhc3Q2NEJ5dGVzTG9uZw==";
    private final long testExpirationMs = 3600000;

    private JwtService jwtService;

    @Mock
    private UserDetails mockUserDetails;

    @BeforeEach
    void setUp() {
        jwtService = new JwtService(testSecretKeyBase64, testExpirationMs);
        jwtService.init();

        when(mockUserDetails.getUsername()).thenReturn("testuser");
        Collection<? extends GrantedAuthority> authorities = Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));
        when(mockUserDetails.getAuthorities()).thenReturn((Collection) authorities);
        when(mockUserDetails.isAccountNonExpired()).thenReturn(true);
        when(mockUserDetails.isAccountNonLocked()).thenReturn(true);
        when(mockUserDetails.isCredentialsNonExpired()).thenReturn(true);
        when(mockUserDetails.isEnabled()).thenReturn(true);
    }

    @Test
    void isTokenValid_shouldReturnFalse_whenTokenIsExpired() {
        log.info("Running test: isTokenValid_shouldReturnFalse_whenTokenIsExpired");
        String expiredToken = jwtService.generateTokenExpiredMinutesAgo(mockUserDetails, 5);
        assertNotNull(expiredToken, "Expired token should not be null");
        log.debug("Generated expired token (first few chars): {}", expiredToken.substring(0, Math.min(expiredToken.length(), 10)));

        boolean isValid = jwtService.isTokenValid(expiredToken, mockUserDetails);
        log.info("Validation result for expired token: {}", isValid);

        assertFalse(isValid, "Expired token should return false from isTokenValid");
    }

    @Test
    void extractUsername_shouldThrowExpiredJwtException_whenTokenIsExpired() {
        log.info("Running test: extractUsername_shouldThrowExpiredJwtException_whenTokenIsExpired");
        String expiredToken = jwtService.generateTokenExpiredMinutesAgo(mockUserDetails, 5);
        assertNotNull(expiredToken, "Expired token for exception test should not be null");
        log.debug("Generated expired token for exception test (first few chars): {}", expiredToken.substring(0, Math.min(expiredToken.length(), 10)));

        ExpiredJwtException exception = assertThrows(ExpiredJwtException.class, () -> {
            jwtService.extractUsername(expiredToken);
        }, "Extracting username from an expired token should throw ExpiredJwtException");

        log.info("Successfully caught expected exception: {}, Message: {}", exception.getClass().getSimpleName(), exception.getMessage());
        assertTrue(exception.getMessage().startsWith("JWT expired"),
                "Exception message should start with 'JWT expired'. Actual: " + exception.getMessage());
    }

    @Test
    void isTokenValid_shouldReturnTrue_whenTokenIsValid() {
        log.info("Running test: isTokenValid_shouldReturnTrue_whenTokenIsValid");
        String validToken = jwtService.generateToken(mockUserDetails);
        assertNotNull(validToken, "Valid token should not be null");
        log.debug("Generated valid token (first few chars): {}", validToken.substring(0, Math.min(validToken.length(), 10)));

        boolean isValid = jwtService.isTokenValid(validToken, mockUserDetails);
        log.info("Validation result for valid token: {}", isValid);

        assertTrue(isValid, "Valid token should return true from isTokenValid");
    }

    @Test
    void isTokenValid_shouldReturnFalse_whenSignatureIsInvalid() {
        log.info("Running test: isTokenValid_shouldReturnFalse_whenSignatureIsInvalid");
        String validToken = jwtService.generateToken(mockUserDetails);
        assertNotNull(validToken, "Valid token for signature test should not be null");

        String tamperedToken = validToken + "a";
        log.debug("Tampered token (first few chars): {}", tamperedToken.substring(0, Math.min(tamperedToken.length(), 10)));

        boolean isValid = jwtService.isTokenValid(tamperedToken, mockUserDetails);
        log.info("Validation result for tampered token: {}", isValid);

        assertFalse(isValid, "Tampered token should return false from isTokenValid");

        assertThrows(SignatureException.class, () -> {
            jwtService.extractUsername(tamperedToken);
        }, "Extracting username from a tampered token should throw SignatureException");
    }

    @Test
    void isTokenValid_shouldReturnFalse_whenUsernameDoesNotMatch() {
        log.info("Running test: isTokenValid_shouldReturnFalse_whenUsernameDoesNotMatch");
        String validToken = jwtService.generateToken(mockUserDetails);
        assertNotNull(validToken, "Valid token for username mismatch test should not be null");

        UserDetails differentUserDetails = User.builder()
                .username("anotheruser")
                .password("password")
                .authorities("ROLE_USER")
                .build();
        log.debug("Generated valid token for 'testuser' (first few chars): {}", validToken.substring(0, Math.min(validToken.length(), 10)));

        boolean isValid = jwtService.isTokenValid(validToken, differentUserDetails);
        log.info("Validation result for token with mismatched user: {}", isValid);

        assertFalse(isValid, "Token valid for 'testuser' should return false for 'anotheruser'");
    }
}
