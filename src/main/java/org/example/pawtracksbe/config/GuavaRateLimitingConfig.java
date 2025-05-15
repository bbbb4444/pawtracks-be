package org.example.pawtracksbe.config;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.util.concurrent.RateLimiter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.TimeUnit;

@Configuration
public class GuavaRateLimitingConfig {

    private static final Logger log = LoggerFactory.getLogger(GuavaRateLimitingConfig.class);

    // --- Configuration for Login Endpoint ---
    // Allow 3 login attempts per minute (0.0833 permits per second)
    private static final double LOGIN_PERMITS_PER_SECOND = 3.0 / 60.0;

    // --- Configuration for Register Endpoint ---
    // Allow 2 registration attempts per hour (0.000833 permits per second)
    private static final double REGISTER_PERMITS_PER_SECOND = 2.0 / 3600.0;

    // --- Configuration for Default API Endpoints ---
    // Example: Allow 50 requests per minute per IP for other authenticated endpoints
    private static final double DEFAULT_API_PERMITS_PER_SECOND = 100.0 / 60.0;

    /**
     * Creates a LoadingCache to store RateLimiter instances per IP address for login.
     * Guava's RateLimiter itself is not directly keyed by IP, so we use a cache for this.
     */
    @Bean("loginRateLimiterCache")
    public LoadingCache<String, RateLimiter> loginRateLimiterCache() {
        return CacheBuilder.newBuilder()
                .maximumSize(10000) // Max number of IP addresses to track
                .expireAfterAccess(10, TimeUnit.MINUTES) // Evict entries after 10 mins of inactivity
                .build(new CacheLoader<String, RateLimiter>() {
                    @Override
                    public RateLimiter load(String key) { // key is the IP address
                        // Create a new RateLimiter for this IP
                        // RateLimiter.create issues permits at a fixed rate.
                        return RateLimiter.create(LOGIN_PERMITS_PER_SECOND);
                    }
                });
    }

    /**
     * Creates a LoadingCache to store RateLimiter instances per IP address for registration.
     */
    @Bean("registerRateLimiterCache")
    public LoadingCache<String, RateLimiter> registerRateLimiterCache() {
        return CacheBuilder.newBuilder()
                .maximumSize(5000) // Max number of IP addresses to track for registration
                .expireAfterAccess(1, TimeUnit.HOURS) // Evict entries after 1 hour of inactivity
                .build(new CacheLoader<String, RateLimiter>() {
                    @Override
                    public RateLimiter load(String key) {
                        return RateLimiter.create(REGISTER_PERMITS_PER_SECOND);
                    }
                });
    }

    @Bean("defaultApiRateLimiterCache")
    public LoadingCache<String, RateLimiter> defaultApiRateLimiterCache() {
        log.info("Creating defaultApiRateLimiterCache bean");
        return CacheBuilder.newBuilder()
                .maximumSize(20000)
                .expireAfterAccess(5, TimeUnit.MINUTES)
                .build(new CacheLoader<String, RateLimiter>() {
                    @Override
                    public RateLimiter load(String key) {
                        return RateLimiter.create(DEFAULT_API_PERMITS_PER_SECOND);
                    }
                });
    }
}

// Interceptor and WebMvcConfigurer (can be in separate files)



