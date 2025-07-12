package org.example.pawtracksbe.security;

import lombok.Getter;
import org.example.pawtracksbe.entity.AppUser;
import org.example.pawtracksbe.entity.RefreshToken;
import org.example.pawtracksbe.exception.TokenRefreshException;
import org.example.pawtracksbe.repository.AppUserRepository;
import org.example.pawtracksbe.repository.JwtRefreshRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class JwtRefreshServiceImpl implements JwtRefreshService {
    @Getter
    @Value("${app.jwt.refresh.expiration-ms}")
    private long refreshExpirationMs;

    AppUserRepository appUserRepository;
    JwtRefreshRepository jwtRefreshRepository;

    @Autowired
    public JwtRefreshServiceImpl(AppUserRepository appUserRepository,
                                 JwtRefreshRepository jwtRefreshRepository) {
        this.appUserRepository = appUserRepository;
        this.jwtRefreshRepository = jwtRefreshRepository;
    }

    public RefreshToken generateRefreshToken(String username) {
        AppUser appUser = appUserRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(appUser);
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshExpirationMs));
        refreshToken.setToken(UUID.randomUUID().toString());

        return jwtRefreshRepository.save(refreshToken);
    }

    public Optional<RefreshToken> findByToken(String token) {
        return jwtRefreshRepository.findByToken(token);
    }

    @Transactional
    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            jwtRefreshRepository.delete(token);
            throw new TokenRefreshException(token.getToken(), "Refresh token was expired. Please make a new signin request");
        }
        return token;
    }

    @Transactional
    public void deleteByUserId(Long userId) {
        jwtRefreshRepository.deleteByUserId(userId);
    }

    @Transactional
    public void deleteByToken(String token) {
        jwtRefreshRepository.deleteByToken(token);
    }
}
