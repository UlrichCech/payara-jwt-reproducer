package de.test.platform.security.boundary;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import javax.ejb.EJB;
import javax.ejb.Singleton;
import javax.inject.Inject;
import javax.inject.Provider;
import java.io.Serializable;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.util.logging.Logger.getLogger;

/**
 * @author Ulrich Cech
 */
@Singleton
public class JWTTokenService implements Serializable {
    private static final long serialVersionUID = 1140953901792439045L;

    private static final Logger logger = getLogger(JWTTokenService.class.getName());

    @EJB
    EncryptionService encryptionService;

    @Inject
    @ConfigProperty(name = "mp.jwt.verify.issuer", defaultValue = "https://example.com")
    Provider<String> jwtIssuer;


    public String generateJWT(String subject, List<String> groups, long expirationTimeInMillis) {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(JOSEObjectType.JWT)
                .keyID("payara-key")
                .build();
        var token = new MPJWTToken();
        token.setAud("payara.fish");
        token.setIss(jwtIssuer.get());
        token.setJti(UUID.randomUUID().toString());
        token.setSub(subject);
        token.setUpn(subject);
        token.setIat(System.currentTimeMillis());
        token.setExp(expirationTimeInMillis);
        token.setGroups(groups);
        var jwsObject = new JWSObject(header, new Payload(token.toJSONString()));
        // Apply the Signing protection
        JWSSigner signer = new RSASSASigner(encryptionService.getPrivateKey());
        try {
            jwsObject.sign(signer);
        } catch (JOSEException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return jwsObject.serialize();
    }

    public Optional<JWTValidationResult> validateToken(String jwtToken) {
        try {
            final var signedJWT = SignedJWT.parse(jwtToken);
            JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) encryptionService.getPublicKey());
            final boolean verified = signedJWT.verify(verifier);
            final boolean expired = new Date().after(signedJWT.getJWTClaimsSet().getExpirationTime());
            return Optional.of(new JWTValidationResult(verified, expired, signedJWT.getJWTClaimsSet().getSubject(), jwtToken));
        } catch (ParseException | JOSEException ex) {
            logger.log(Level.SEVERE, "Technical error while validating JWT.", ex);
        }
        return Optional.empty();
    }

}
