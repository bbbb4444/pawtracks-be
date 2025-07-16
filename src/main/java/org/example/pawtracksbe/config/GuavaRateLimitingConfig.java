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

    private static final double LOGIN_PERMITS_PER_SECOND = 3.0 / 60.0;
    private static final double REGISTER_PERMITS_PER_SECOND = 2.0 / 3600.0;
    private static final double DEFAULT_API_PERMITS_PER_SECOND = 100.0 / 60.0;

    @Bean("loginRateLimiterCache")
    public LoadingCache<String, RateLimiter> loginRateLimiterCache() {
        return CacheBuilder.newBuilder()
                .maximumSize(10000)
                .expireAfterAccess(10, TimeUnit.MINUTES)
                .build(new CacheLoader<String, RateLimiter>() {
                    @Override
                    public RateLimiter load(String key) {
                        return RateLimiter.create(LOGIN_PERMITS_PER_SECOND);
                    }
                });
    }

    @Bean("registerRateLimiterCache")
    public LoadingCache<String, RateLimiter> registerRateLimiterCache() {
        return CacheBuilder.newBuilder()
                .maximumSize(5000)
                .expireAfterAccess(1, TimeUnit.HOURS)
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



