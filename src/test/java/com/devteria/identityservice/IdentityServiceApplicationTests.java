package com.devteria.identityservice;

import jakarta.xml.bind.DatatypeConverter;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

@SpringBootTest
@Slf4j
class IdentityServiceApplicationTests {

    @Test
    void hash() throws NoSuchAlgorithmException {
        String password = "12345678";
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(password.getBytes());
        byte[] hash = md.digest(password.getBytes());
        String hashString = DatatypeConverter.printHexBinary(hash);
        log.info("round 2: {}", hashString);

        md.update(password.getBytes());
        byte[] hash2 = md.digest(password.getBytes());
        String hashString2 = DatatypeConverter.printHexBinary(hash2);
        log.info("round 1: {}", hashString2);

        MessageDigest md2 = MessageDigest.getInstance("MD5");
        md2.update(password.getBytes());
        byte[] hash3 = md2.digest(password.getBytes());
        String hashString3 = DatatypeConverter.printHexBinary(hash3);
        log.info("round 2: {}", hashString3);

        md2.update(password.getBytes());
        byte[] hash4 = md2.digest(password.getBytes());
        String hashString4 = DatatypeConverter.printHexBinary(hash4);
        log.info("round 1: {}", hashString4);
    }

}
