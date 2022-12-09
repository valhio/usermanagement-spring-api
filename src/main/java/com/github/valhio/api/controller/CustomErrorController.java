package com.github.valhio.api.controller;

import com.github.valhio.api.domain.HttpResponse;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.Date;

import static org.springframework.http.HttpStatus.NOT_FOUND;

@Controller
@RequestMapping("/error")
public class CustomErrorController implements ErrorController {

    @RequestMapping
    public ResponseEntity<HttpResponse> handleError() {
        HttpResponse build = HttpResponse.builder()
                .statusCode(NOT_FOUND.value())
                .status(NOT_FOUND)
                .reason(NOT_FOUND.getReasonPhrase().toUpperCase())
                .message("This page does not exist")
                .timeStamp(new Date())
                .build();

        return new ResponseEntity<>(build, NOT_FOUND);
    }
}
