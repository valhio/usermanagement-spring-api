package com.github.valhio.api.controller;

import com.github.valhio.api.domain.HttpResponse;
import com.github.valhio.api.exception.ExceptionHandling;
import com.github.valhio.api.exception.domain.EmailExistException;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Date;

import static org.springframework.http.HttpStatus.NOT_FOUND;

@RestController
@RequestMapping(path = {"/api/v1/user"})
public class UserController extends ExceptionHandling {

    @GetMapping("/home")
    public String home() throws EmailExistException {
        throw new EmailExistException("Email already exist");
//        return "Application is running!";
    }
}
