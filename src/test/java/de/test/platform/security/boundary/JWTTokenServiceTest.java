package de.test.platform.security.boundary;


import org.junit.jupiter.api.Test;

import java.util.Collections;

/**
 * @author Ulrich Cech
 */
class JWTTokenServiceTest {

    @Test
    void generateJWT() {
        JWTTokenService tokenService = new JWTTokenService();
        tokenService.encryptionService = new EncryptionService(
                "gc3xmQ82dyq0noHy4fwtNduDN8SM6lGOK8+76JWgPsI=",
                EncryptionService.privateKey
        );
        tokenService.encryptionService.init();
        tokenService.jwtIssuer = () -> "https://example.com";

        final String jwt = tokenService
                .generateJWT("testsubject",
                        Collections.singletonList("ALL_USERS"),
                        System.currentTimeMillis());
        System.out.println(jwt);
    }

}