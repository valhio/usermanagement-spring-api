package com.github.valhio.api;


import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.Arrays;
import java.util.Collections;

@SpringBootApplication
public class ApiApplication {

    public static void main(String[] args) {
        SpringApplication.run(ApiApplication.class, args);
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // CORS (Cross-Origin Resource Sharing) is a mechanism that uses additional HTTP headers to tell a browser
    // to let a web application running at one origin (domain) have permission to access selected resources
    // from a server at a different origin. A web application executes a cross-origin HTTP request when it
    // requests a resource that has a different origin (domain, protocol, or port) from its own.
    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource urlBasedCorsConfigurationSource = new UrlBasedCorsConfigurationSource(); // This is the source of the CORS configuration
        CorsConfiguration corsConfiguration = new CorsConfiguration(); // This is the actual CORS configuration
        corsConfiguration.setAllowCredentials(true); // This allows cookies to be sent with the CORS request
        corsConfiguration.setAllowedOrigins(Collections.singletonList("http://localhost:4200")); // This allows requests from http://localhost:4200
        corsConfiguration.setAllowedHeaders(Arrays.asList("Origin", "Access-Control-Allow-Origin", "Content-Type",
                "Accept", "Jwt-Token", "Authorization", "Origin, Accept", "X-Requested-With",
                "Access-Control-Request-Method", "Access-Control-Request-Headers")); // This allows the following headers in the request to be sent
        corsConfiguration.setExposedHeaders(Arrays.asList("Origin", "Content-Type", "Accept", "Jwt-Token", "Authorization",
                "Access-Control-Allow-Origin", "Access-Control-Allow-Credentials")); // This allows the following headers in the response to be exposed to the client
        corsConfiguration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS")); // This allows the following methods to be used in the request
        urlBasedCorsConfigurationSource.registerCorsConfiguration("/**", corsConfiguration); // This registers the CORS configuration
        return new CorsFilter(urlBasedCorsConfigurationSource); // This returns the CORS filter
    }

}
