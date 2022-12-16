package com.github.valhio.api.service;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import org.springframework.stereotype.Service;

import java.util.Map;

/*
 *   This class is used to keep track of the number of failed login attempts for a user and lock the user out if the number of failed login attempts exceeds a threshold.
 * */

@Service
public class LoginAttemptService {
    private static final int MAX_ATTEMPT = 5;
    private static final int ATTEMPT_INCREMENT = 1;
    private LoadingCache<String, Integer> attemptsCache;
    // LoadingCache is a Guava cache that automatically loads new values into the cache when requested.
    // This is useful for caches that do not have an obvious or easy way to pre-populate, such as caches that load values from a database or web service.

    // The CacheBuilder class is used to create instances of LoadingCache.
    public LoginAttemptService() {
        super();
        this.attemptsCache = CacheBuilder.newBuilder()
                .maximumSize(100) // In case the cache reaches its maximum size, the cache will evict entries that are least recently used.
                .expireAfterWrite(15, java.util.concurrent.TimeUnit.MINUTES)
                .build(new CacheLoader<String, Integer>() {
                    @Override
                    public Integer load(String username) throws Exception {
                        return 0;
                    }
                });
    }

    // This method is used to reset the number of failed login attempts for a user.
    public void loginSucceeded(String username) {
        attemptsCache.invalidate(username);
    }

    // This method is used to increment the number of failed login attempts for a user.
    public void loginFailed(String username) {
        int attempts = 0;
        try {
            attempts = ATTEMPT_INCREMENT + attemptsCache.get(username);
        } catch (Exception e) {
            attempts = ATTEMPT_INCREMENT;
        }
        attemptsCache.put(username, attempts);
    }

    // This method is used to check if a user is locked out.
    public boolean isBlocked(String username) {
        try {
            return attemptsCache.get(username) >= MAX_ATTEMPT;
        } catch (Exception e) {
            return false;
        }
    }

    // This method is used to get the number of failed login attempts for a user.
    public Map<String, Integer> getAttemptsCache() {
        return attemptsCache.asMap();
    }

    // This method is used to clear the cache.
    public void clearCache() {
        attemptsCache.invalidateAll();
    }

}
