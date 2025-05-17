package org.example.pawtracksbe.config;

import com.google.common.cache.LoadingCache;
import com.google.common.util.concurrent.RateLimiter;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
class GuavaWebMvcConfig implements WebMvcConfigurer {

    private final LoadingCache<String, RateLimiter> loginRateLimiterCache;
    private final LoadingCache<String, RateLimiter> registerRateLimiterCache;
    private final LoadingCache<String, RateLimiter> defaultApiRateLimiterCache;

    public GuavaWebMvcConfig(
            @Qualifier("loginRateLimiterCache")
            LoadingCache<String, RateLimiter> loginRateLimiterCache,
            @Qualifier("registerRateLimiterCache")
            LoadingCache<String, RateLimiter> registerRateLimiterCache,
            @Qualifier("defaultApiRateLimiterCache")
            LoadingCache<String, RateLimiter> defaultApiRateLimiterCache) {
        this.loginRateLimiterCache = loginRateLimiterCache;
        this.registerRateLimiterCache = registerRateLimiterCache;
        this.defaultApiRateLimiterCache = defaultApiRateLimiterCache;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new GuavaRateLimitInterceptor(loginRateLimiterCache, "LoginLimiter"))
                .addPathPatterns("/api/auth/login");

        registry.addInterceptor(new GuavaRateLimitInterceptor(registerRateLimiterCache, "RegisterLimiter"))
                .addPathPatterns("/api/auth/register");
    }
}