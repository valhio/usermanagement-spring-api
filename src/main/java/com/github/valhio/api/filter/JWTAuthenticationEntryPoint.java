package com.github.valhio.api.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.valhio.api.domain.HttpResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Date;

import static com.github.valhio.api.constant.SecurityConstant.FORBIDDEN_MESSAGE;

/*
 *   This class is used to return a 403 error code to clients that try to access a protected resource without proper authentication.
 *  (Client is not logged in)
 * */
@Component
public class JWTAuthenticationEntryPoint extends Http403ForbiddenEntryPoint {

    // This method is called whenever an exception is thrown due to an unauthenticated user trying to access a resource that requires authentication.
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        // Create a new HttpResponse object with the 403 status code and the FORBIDDEN_MESSAGE message.
        HttpResponse httpResponse = HttpResponse.builder()
                .statusCode(403)
                .status(HttpStatus.FORBIDDEN)
                .reason(HttpStatus.FORBIDDEN.getReasonPhrase().toUpperCase())
                .message(FORBIDDEN_MESSAGE)
                .timeStamp(new Date())
                .build();

        response.setContentType("application/json");
        response.setStatus(HttpStatus.FORBIDDEN.value());

        // Write the HttpResponse object to the response output stream.
        OutputStream outputStream = response.getOutputStream(); // Get the output stream from the response.
        ObjectMapper mapper = new ObjectMapper(); // Create a new ObjectMapper object.
        mapper.writeValue(outputStream, httpResponse); // Write the HttpResponse object to the output stream.
        outputStream.flush(); // Flush the output stream.
    }
}
