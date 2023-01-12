package com.github.valhio.api.config;

import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@Configuration
@EnableCaching
@EnableJpaAuditing
public class JpaEnversConfiguration {
//
//    @Bean
//    public ModelMapper modelMapper() {
//        return new ModelMapper();
//    }

    @Bean
    AuditorAware<String> auditorAware() {
        return new SpringSecurityAuditorAware();
    }
}
