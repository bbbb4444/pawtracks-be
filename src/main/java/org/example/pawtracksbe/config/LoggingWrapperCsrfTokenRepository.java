package org.example.pawtracksbe.config; // Or your appropriate config/security package

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.DeferredCsrfToken; // Keep this import

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

    // generateToken, saveToken, loadToken methods remain the same as previously provided

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

    // CORRECTED loadDeferredToken
    @Override
    public DeferredCsrfToken loadDeferredToken(HttpServletRequest request, HttpServletResponse response) {
        String uri = request.getRequestURI();
        log.info("WRAPPER [{}] > loadDeferredToken - URI: {}", repositoryId, uri);

        // Call the delegate's loadDeferredToken. It will return its own DeferredCsrfToken (likely an instance of the internal DefaultDeferredCsrfToken).
        final DeferredCsrfToken delegateDeferredToken = delegate.loadDeferredToken(request, response);

        // Wrap the DeferredCsrfToken returned by the delegate so we can log its operations
        // without needing to know about DefaultDeferredCsrfToken.
        DeferredCsrfToken loggingDeferredToken = new DeferredCsrfToken() {
            private CsrfToken cachedToken = null; // Cache to avoid multiple supplier calls if not needed by underlying
            private boolean hasBeenLoaded = false;

            @Override
            public CsrfToken get() {
                // This logging happens when deferredCsrfToken.get() is called by CsrfFilter or CsrfTokenRequestHandler
                log.info("WRAPPER [{}] DeferredCsrfToken.get() called - URI: {}", repositoryId, request.getRequestURI());
                if (!hasBeenLoaded) { // Simple caching to mimic potential behavior, though underlying delegate might do its own
                    cachedToken = delegateDeferredToken.get(); // Call the actual delegate's get()
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

            // The save functionality is typically handled when the response is committed,
            // often triggered by CsrfFilter's response wrapper.
            // The runnable inside the original DefaultDeferredCsrfToken (created by the delegate)
            // will call the delegate's saveToken(delegateSupplier.get(), ...).
            // Our wrapped saveToken and loadToken methods will be hit if that's how the delegate is structured.
            // We don't need to explicitly manage the save runnable here if we are just wrapping.
            // The key is that the delegate's DeferredCsrfToken's supplier and runnable will eventually call
            // the delegate's loadToken and saveToken, which our wrapper intercepts.
        };

        log.info("WRAPPER [{}] < loadDeferredToken - URI: {}, Wrapped delegate's DeferredCsrfToken.", repositoryId, uri);
        return loggingDeferredToken;
    }
}