package com.github.valhio.api.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.valhio.api.domain.HttpResponse;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.OutputStream;

import static com.github.valhio.api.constant.SecurityConstant.ACCESS_DENIED_MESSAGE;
/**
 * This class is used to return a 403 error code to clients that try to access a protected resource without proper authentication.
 * (They do not have the required role).
 */
@Component
public class JWTAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        // Create a new HttpResponse object with the 403 status code and the FORBIDDEN_MESSAGE message.
        HttpResponse httpResponse = HttpResponse.builder()
                .statusCode(403)
                .status(HttpStatus.UNAUTHORIZED)
                .reason(HttpStatus.UNAUTHORIZED.getReasonPhrase().toUpperCase())
                .message(ACCESS_DENIED_MESSAGE)
                .build();

        response.setContentType("application/json");
        response.setStatus(HttpStatus.FORBIDDEN.value());

        // Write the HttpResponse object to the response output stream.
        OutputStream outputStream = response.getOutputStream(); // Get the output stream from the response.
        ObjectMapper mapper = new ObjectMapper(); // Create a new ObjectMapper object.
        mapper.writeValue(outputStream, httpResponse); // Write the HttpResponse object to the output stream.
        outputStream.flush(); // Flush the output stream.    }
    }
}
