package org.example.pawtracksbe.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.DeferredCsrfToken;

import java.util.UUID;

public class LoggingWrapperCsrfTokenRepository implements CsrfTokenRepository {
    private static final Logger log = LoggerFactory.getLogger(LoggingWrapperCsrfTokenRepository.class);
    private final CsrfTokenRepository delegate;
    private final String repositoryId = UUID.randomUUID().toString().substring(0, 6);

    public LoggingWrapperCsrfTokenRepository(CsrfTokenRepository delegate) {
        if (delegate == null) {
            throw new IllegalArgumentException("Delegate CsrfTokenRepository cannot be null");
        }
        this.delegate = delegate;
        log.info("LoggingWrapperCsrfTokenRepository [{}] initialized, wrapping delegate: {}",
                repositoryId, delegate.getClass().getName());
    }

    @Override
    public CsrfToken generateToken(HttpServletRequest request) {
        String uri = request.getRequestURI();
        log.info("WRAPPER [{}] > generateToken - URI: {}", repositoryId, uri);
        CsrfToken token = delegate.generateToken(request);
        if (token != null) {
            log.info("WRAPPER [{}] < generateToken - URI: {}, Generated Token Value: '{}', Header: '{}', Param: '{}'",
                    repositoryId, uri, token.getToken(), token.getHeaderName(), token.getParameterName());
        } else {
            log.warn("WRAPPER [{}] < generateToken - URI: {}, Generated NULL Token", repositoryId, uri);
        }
        return token;
    }

    @Override
    public void saveToken(CsrfToken token, HttpServletRequest request, HttpServletResponse response) {
        String uri = request.getRequestURI();
        String tokenValueToSave = (token != null) ? token.getToken() : "NULL (will clear cookie)";
        log.info("WRAPPER [{}] > saveToken - URI: {}, Token to Save: '{}'",
                repositoryId, uri, tokenValueToSave);

        if (token == null) {
            log.warn("WRAPPER [{}] > saveToken - URI: {}, Details: Saving a NULL token. " +
                            "The delegate ({}) will likely set Max-Age=0 to clear the cookie.",
                    repositoryId, uri, delegate.getClass().getSimpleName());
        }
        delegate.saveToken(token, request, response);
        log.info("WRAPPER [{}] < saveToken - URI: {}, Delegate's saveToken executed.", repositoryId, uri);
    }

    @Override
    public CsrfToken loadToken(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String removedAttrName = "org.springframework.security.web.csrf.CookieCsrfTokenRepository.REMOVED";
        boolean tokenMarkedAsRemoved = Boolean.TRUE.equals(request.getAttribute(removedAttrName));

        log.info("WRAPPER [{}] > loadToken - URI: {}, Request Attribute '{}' is: {}",
                repositoryId, uri, removedAttrName, tokenMarkedAsRemoved);

        CsrfToken token = delegate.loadToken(request);

        if (token != null) {
            log.info("WRAPPER [{}] < loadToken - URI: {}, Loaded Token Value: '{}', Header: '{}', Param: '{}'",
                    repositoryId, uri, token.getToken(), token.getHeaderName(), token.getParameterName());
        } else {
            log.info("WRAPPER [{}] < loadToken - URI: {}, Loaded NULL Token. (Was cookie present? Was attribute '{}' true?)",
                    repositoryId, uri, removedAttrName);
        }
        return token;
    }

    @Override
    public DeferredCsrfToken loadDeferredToken(HttpServletRequest request, HttpServletResponse response) {
        String uri = request.getRequestURI();
        log.info("WRAPPER [{}] > loadDeferredToken - URI: {}", repositoryId, uri);

        final DeferredCsrfToken delegateDeferredToken = delegate.loadDeferredToken(request, response);

        DeferredCsrfToken loggingDeferredToken = new DeferredCsrfToken() {
            private CsrfToken cachedToken = null;
            private boolean hasBeenLoaded = false;

            @Override
            public CsrfToken get() {
                log.info("WRAPPER [{}] DeferredCsrfToken.get() called - URI: {}", repositoryId, request.getRequestURI());
                if (!hasBeenLoaded) {
                    cachedToken = delegateDeferredToken.get();
                    hasBeenLoaded = true;
                    if (cachedToken != null) {
                        log.info("WRAPPER [{}] DeferredCsrfToken.get() - Loaded from delegate: '{}'", repositoryId, cachedToken.getToken());
                    } else {
                        log.info("WRAPPER [{}] DeferredCsrfToken.get() - Loaded NULL from delegate", repositoryId);
                    }
                } else {
                    log.info("WRAPPER [{}] DeferredCsrfToken.get() - Returning cached token: '{}'", repositoryId, (cachedToken !=null? cachedToken.getToken() : "NULL"));
                }
                return cachedToken;
            }

            @Override
            public boolean isGenerated() {
                boolean isGen = delegateDeferredToken.isGenerated();
                log.info("WRAPPER [{}] DeferredCsrfToken.isGenerated() called - URI: {}, Result: {}", repositoryId, request.getRequestURI(), isGen);
                return isGen;
            }
        };

        log.info("WRAPPER [{}] < loadDeferredToken - URI: {}, Wrapped delegate's DeferredCsrfToken.", repositoryId, uri);
        return loggingDeferredToken;
    }
}