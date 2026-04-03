package com.devteria.identityservice.service;

import com.devteria.identityservice.dto.request.AuthenticationRequest;
import com.devteria.identityservice.dto.request.IntrospectTokenRequest;
import com.devteria.identityservice.dto.response.AuthenticationRespone;
import com.devteria.identityservice.dto.response.IntrospectTokenRespone;
import com.devteria.identityservice.entity.User;
import com.devteria.identityservice.exception.AppException;
import com.devteria.identityservice.exception.ErrorCode;
import com.devteria.identityservice.repository.UserRepository;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Set;
import java.util.StringJoiner;

@Service
@RequiredArgsConstructor
@Slf4j
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class AuthenticationService {
    UserRepository userRepository;
    PasswordEncoder passwordEncoder;

    @NonFinal
    @Value("${jwt.signerKey}")
    protected String SIGNER_KEY;

    public IntrospectTokenRespone introspectToken(IntrospectTokenRequest introspectTokenRequest)
            throws JOSEException, ParseException {
        var token = introspectTokenRequest.getToken();
        JWSVerifier verifier = new MACVerifier(SIGNER_KEY.getBytes());
        SignedJWT jwt = SignedJWT.parse(token);
        Date expireTime = jwt.getJWTClaimsSet().getExpirationTime();
        var result = jwt.verify(verifier) && expireTime.after(new Date());
        return IntrospectTokenRespone.builder()
                .valid(result)
                .build();
    }
    public AuthenticationRespone authenticate(AuthenticationRequest authenticationRequest) {
        var authenticatedUser = userRepository
                .findByUsername(authenticationRequest.getUsername())
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));
        boolean result = passwordEncoder.matches(authenticationRequest.getPassword(), authenticatedUser.getPassword());
        if (!result) {
            throw new AppException(ErrorCode.AUTHENTICATED);
        }
        var token = generateToken(authenticatedUser);
        return AuthenticationRespone.builder()
                .authenticated(true)
                .token(token)
                .build();
    }

    private String generateToken(User user) {
        JWSHeader header = new JWSHeader(JWSAlgorithm.HS512);
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer("vinhvh")
                .subject(user.getUsername())
                .issueTime(new Date())
                .claim("scope", buildScope(user.getRoles()))
                .expirationTime(new Date(
                        Instant.now().plus(2, ChronoUnit.HOURS).toEpochMilli()
                )).build();
        Payload payload = new Payload(claimsSet.toJSONObject());
        JWSObject jwsOject = new JWSObject(header, payload);
        try {
            jwsOject.sign(new MACSigner(SIGNER_KEY.getBytes()));
            return jwsOject.serialize();
        } catch (JOSEException e) {
            log.error(e.getMessage(), e);
            throw new RuntimeException(e);
        }

    }

    private String buildScope(Set<String> roles) {
        if (roles.isEmpty()) {
            return "";
        }
        StringJoiner stringJoiner = new StringJoiner(" ");
        roles.forEach(stringJoiner::add);
        return stringJoiner.toString();
    }
}
