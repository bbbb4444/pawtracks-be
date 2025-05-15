package org.example.pawtracksbe.config;

import com.google.common.cache.LoadingCache;
import com.google.common.util.concurrent.RateLimiter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.concurrent.ExecutionException;

public class GuavaRateLimitInterceptor implements HandlerInterceptor {

    private static final Logger log = LoggerFactory.getLogger(GuavaRateLimitInterceptor.class);

    private final LoadingCache<String, RateLimiter> rateLimiterCache;
    private final String rateLimiterName;

    public GuavaRateLimitInterceptor(LoadingCache<String, RateLimiter> rateLimiterCache, String rateLimiterName) {
        this.rateLimiterCache = rateLimiterCache;
        this.rateLimiterName = rateLimiterName;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String ipAddress = getClientIP(request);
        if (ipAddress == null) {
            log.warn("GuavaRateLimitInterceptor ({}): Could not determine client IP. Allowing request.", rateLimiterName);
            return true; // Or deny based on policy
        }

        RateLimiter limiter;
        try {
            limiter = rateLimiterCache.get(ipAddress);
        } catch (ExecutionException e) {
            log.error("GuavaRateLimitInterceptor ({}): Error retrieving RateLimiter for IP {}. Allowing request.", rateLimiterName, ipAddress, e);
            return true;
        }

        // tryAcquire() attempts to acquire a permit. Returns true if acquired, false otherwise.
        // It does not block.
        if (limiter.tryAcquire()) {
            log.debug("GuavaRateLimitInterceptor ({}): Permit acquired for IP {}.", rateLimiterName, ipAddress);
            return true; // Request allowed
        } else {
            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value()); // 429
            response.getWriter().write("Too many requests. Please try again later.");
            log.warn("GuavaRateLimitInterceptor ({}): Rate limit exceeded for IP {}.", rateLimiterName, ipAddress);
            // Guava's RateLimiter doesn't easily provide a "retry-after" time in the same way
            // as Bucket4j's ConsumptionProbe. You could add a generic header.
            response.addHeader("Retry-After", "60"); // Suggest retrying after 60 seconds (example)
            return false; // Request denied
        }
    }

    private String getClientIP(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null || xfHeader.isEmpty() || "unknown".equalsIgnoreCase(xfHeader)) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0];
    }
}