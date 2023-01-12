package com.github.valhio.api.config;

import org.springframework.data.domain.AuditorAware;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

public class SpringSecurityAuditorAware implements AuditorAware<String> {
//    https://stackoverflow.com/questions/66498894/spring-boot-auditing-map-current-user-to-createdby-lastmodifiedby
//    https://www.youtube.com/watch?v=LE_oknOU_U0&list=PL9l1zUfnZkZnfOFgWa4K9lTzhvCkjTQfm&index=57

    @Override
    public Optional<String> getCurrentAuditor() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();

        return Optional.ofNullable(username);
    }
}