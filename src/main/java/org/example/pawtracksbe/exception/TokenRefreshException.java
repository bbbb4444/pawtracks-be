package org.example.pawtracksbe.exception;

public class TokenRefreshException extends RuntimeException {
    public TokenRefreshException(String token, String message) {
        super(message);
    }
}
