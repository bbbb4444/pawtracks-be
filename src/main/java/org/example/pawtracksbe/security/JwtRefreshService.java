package org.example.pawtracksbe.security;

import org.example.pawtracksbe.entity.RefreshToken;

import java.util.Optional;

public interface JwtRefreshService {
    RefreshToken generateRefreshToken(String username);
    Optional<RefreshToken> findByToken(String token);
    RefreshToken verifyExpiration(RefreshToken token);
    void deleteByUserId(Long userId);
    void deleteByToken(String token);
}
