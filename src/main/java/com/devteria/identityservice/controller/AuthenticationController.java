package com.devteria.identityservice.controller;

import com.devteria.identityservice.dto.request.ApiResponse;
import com.devteria.identityservice.dto.request.AuthenticationRequest;
import com.devteria.identityservice.dto.request.IntrospectTokenRequest;
import com.devteria.identityservice.dto.response.AuthenticationRespone;
import com.devteria.identityservice.dto.response.IntrospectTokenRespone;
import com.devteria.identityservice.service.AuthenticationService;
import com.nimbusds.jose.JOSEException;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.text.ParseException;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class AuthenticationController {
    AuthenticationService authenticationService;
    @PostMapping("/login")
    ApiResponse<AuthenticationRespone> authenticate(@RequestBody AuthenticationRequest authenticationRequest){
        AuthenticationRespone result = authenticationService.authenticate(authenticationRequest);
        return ApiResponse.<AuthenticationRespone>builder()
                .result(result)
                .build();
    }

    @PostMapping("introspect")
    ApiResponse<IntrospectTokenRespone> authenticate(@RequestBody IntrospectTokenRequest introspectTokenRequest) throws ParseException, JOSEException {
        var result = authenticationService.introspectToken(introspectTokenRequest);
        return ApiResponse.<IntrospectTokenRespone>builder()
                .result(result)
                .build();
    }
}
