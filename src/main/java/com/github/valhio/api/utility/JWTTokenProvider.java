package com.github.valhio.api.utility;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.github.valhio.api.model.UserPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;

import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import static com.github.valhio.api.constant.SecurityConstant.*;
import static java.util.Arrays.stream;

/*
*   This class is used to generate and validate JWT tokens.
* */

public class JWTTokenProvider {

    @Value("${jwt.secret}")
    private String secretKey;

    public String generateJWTToken(UserPrincipal userPrincipal) {
        String[] claims = getClaimsFromUser(userPrincipal);
        return JWT.create()
                .withIssuer(KBDA_LLC) // Who created the token
                .withAudience(KBDA_LLC_ADMINISTRATION) // Who is the token for
                .withIssuedAt(new Date()) // When was the token issued
                .withSubject(userPrincipal.getUsername()) // What is the subject of the token, in this case the username (unique identifier)
                .withArrayClaim(AUTHORITIES, claims) // What are the claims of the token, in this case, the authorities
                .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_TIME)) // When does the token expire
                .sign(com.auth0.jwt.algorithms.Algorithm.HMAC512(secretKey.getBytes())); // What is the secret key used to sign the token
    }

    public List<? extends GrantedAuthority> getAuthorities(String token) {
        String[] claims = getClaimsFromToken(token);
        return stream(claims).map(SimpleGrantedAuthority::new).collect(Collectors.toList());
    }

    public Authentication getAuthentication(String username, List<? extends GrantedAuthority> authorities, HttpServletRequest request) {
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(username, null, authorities); // Username, credentials, authorities. Credentials are not needed because we have already verified the token
        usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request)); // Set the details of the request (IP address, session ID, etc)
        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken); // Set the authentication in the Security Context
        return usernamePasswordAuthenticationToken; // Return the authentication
    }

    public boolean isTokenValid(String username, String token) {
        // Verify the token and check if the subject is the same as the username
        return username.equals(getSubject(token)) && !isTokenExpired(getJWTVerifier(), token); // Check if the subject is the same as the username and if the token is not expired
    }

    private boolean isTokenExpired(JWTVerifier verifier, String token) {
        Date expiration = verifier.verify(token).getExpiresAt(); // Get the expiration date from the token
        return expiration.before(new Date()); // Check if the expiration date is before the current date
    }

    private JWTVerifier getJWTVerifier() {
        // Create a verifier for the token using the secret key and issuer, and return it
        JWTVerifier verifier;
        try {
            verifier = JWT.require(Algorithm.HMAC512(secretKey)).withIssuer(KBDA_LLC).build();
        } catch (Exception e) {
            throw new JWTVerificationException(TOKEN_CANNOT_BE_VERIFIED);
        }
        return verifier;
    }


    private String[] getClaimsFromUser(UserPrincipal userPrincipal) {
        // Get the authorities from the user and return them as an array of strings
        return userPrincipal.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toArray(String[]::new);
    }

    private String[] getClaimsFromToken(String token) {
        return getJWTVerifier() // Get the verifier
                .verify(token) // Verifies the token
                .getClaim(AUTHORITIES) // What are the claims of the token, in this case, the authorities
                .asArray(String.class);
    }

    public String getSubject(String token) {
        return getJWTVerifier().verify(token).getSubject();
    }
}
