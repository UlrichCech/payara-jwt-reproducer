package de.test.platform.security.boundary;

import de.test.platform.PlatformException;
import de.test.platform.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import javax.annotation.PostConstruct;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.ejb.Singleton;
import javax.ejb.Startup;
import javax.inject.Inject;
import javax.inject.Provider;
import java.io.IOException;
import java.io.StringReader;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.util.logging.Logger.getLogger;

/**
 * @author Ulrich Cech
 */
@Singleton
@Startup
public class EncryptionService {

    private static final Logger logger = getLogger(EncryptionService.class.getName());

    public static final String ENC_PREFIX ="--ENC--";


    @Inject
    @ConfigProperty(name = "PAYARA_MASTER_KEY", defaultValue = "gc3xmQ82dyq0noHy4fwtNduDN8SM6lGOK8+76JWgPsI=")
    Provider<String> masterKeyAsString;

    @Inject
    @ConfigProperty(name = "PAYARA_MASTER_KEYPAIR", defaultValue = privateKey)
    Provider<String> masterKeypairAsString;




    private KeyPair masterKeyPair;

    private SecretKey masterKey;


    public EncryptionService() {
    }

    public EncryptionService(final String masterKeyAsString, final String masterKeypairAsString) {
        this.masterKeyAsString = () -> masterKeyAsString;
        this.masterKeypairAsString = () -> masterKeypairAsString;
        init();
    }

    @PostConstruct
    public void init() {
        this.masterKeyPair = createKeyPair();
        this.masterKey = createKey();
    }


    public SecretKey createAES256Key() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256, SecureRandom.getInstanceStrong());
        return keyGen.generateKey();
    }

    public SecretKey createAES256KeyFromBase64Encoded(final String encodedKey) {
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }


    public String encryptDataToBase64(String value, String prefix) {
        var encryptedData = encryptData(value.getBytes(StandardCharsets.UTF_8));
        return prefix + Base64.getEncoder().encodeToString(encryptedData);
    }

    public byte[] encryptData(byte[] dataToEncrypt) {
        try {
            SecureRandom secureRandom = new SecureRandom();
            byte[] iv = new byte[12]; //NEVER REUSE THIS IV WITH SAME KEY
            secureRandom.nextBytes(iv);
            final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv); //128 bit auth tag length
            cipher.init(Cipher.ENCRYPT_MODE, masterKey, parameterSpec);
            byte[] cipherText = cipher.doFinal(dataToEncrypt);

            ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + cipherText.length);
            byteBuffer.put(iv);
            byteBuffer.put(cipherText);
            return byteBuffer.array();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
            throw new PlatformException(ex);
        }
    }

    public byte[] decryptDataFromBase64(String encryptedAndBase64EncodedValue, String prefix) {
        if (StringUtils.isNotBlank(encryptedAndBase64EncodedValue)) {
            String encValue = encryptedAndBase64EncodedValue;
            if (StringUtils.isNotBlank(prefix)) {
                encValue = encryptedAndBase64EncodedValue.substring(prefix.length());
            }
            return decryptData(Base64.getDecoder().decode(encValue));
        }
        throw new PlatformException("Nothing to decrypt!");
    }

    public byte[] decryptData(byte[] cipherMessage) {
        try {
            final Cipher decryptCipher = Cipher.getInstance("AES/GCM/NoPadding");
            //use first 12 bytes for iv
            AlgorithmParameterSpec gcmIv = new GCMParameterSpec(128, cipherMessage, 0, 12);
            decryptCipher.init(Cipher.DECRYPT_MODE, masterKey, gcmIv);
            //use everything from 12 bytes on as ciphertext
            return decryptCipher.doFinal(cipherMessage, 12, cipherMessage.length - 12);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
            throw new PlatformException(ex);
        }
    }


    private KeyPair createKeyPair() {
        if ((masterKeypairAsString != null) && StringUtils.isNotBlank(masterKeypairAsString.get())) {
            String privKeyString = masterKeypairAsString.get().replace("###", "\n");
            try (var keyReader = new StringReader(privKeyString);
                 var pemParser = new PEMParser(keyReader)) {
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(new BouncyCastleProvider());
                var object = pemParser.readObject();
                return converter.getKeyPair((PEMKeyPair) object);
            } catch (IOException ex) {
                logger.log(Level.SEVERE, "PrivateKey does not exist or is damaged.", ex);
            }
        }
        throw new PlatformException("Fehler");
    }

    private SecretKey createKey() {
        if ((masterKeyAsString != null) && StringUtils.isNotBlank(masterKeyAsString.get())) {
            return createAES256KeyFromBase64Encoded(masterKeyAsString.get());
        }
        throw new PlatformException("Fehler");
    }

    public PublicKey getPublicKey() {
        return masterKeyPair.getPublic();
    }

    public PrivateKey getPrivateKey() {
        return masterKeyPair.getPrivate();
    }

    public SecretKey getMasterKey() {
        return masterKey;
    }

    public static final String privateKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIIEpQIBAAKCAQEAz4BOwrW0aeEoznMJWCkYfMYr8uEZXvgZkZh5HdwwGU3bhaQO\n" +
            "yLQ8DlH6WOKE24pdy2Im7h3FYJSAXBhDvL16sZNP456omJPztOBczehZ0Rf7aYkc\n" +
            "yHIvPbDAWQ64ieQl10OJ03TsIPXaXZccBZXGW3p5bI2b4Iybh9pCmmWENg8YHfcu\n" +
            "Eo3nD5qAitsp21hreLazw6JVrz7vYPylbpYyJFkReOVrPsj7yAV6xakHDozSnFCL\n" +
            "N+uBhA4anFt6HtvzTb8Z+2HcfK6eREktsRlWVteMK3ti48cn3+ouS+uPrTdUN8ro\n" +
            "mVYaWLz86dyNqEq+88aKn7JgHw/C+5mJf6dQPwIDAQABAoIBAQCD8Moj9PYq/Qi9\n" +
            "fVhLvpXbgQchARDo2kkn0xPwcLoE3QThDVh5NmGZmXbeXeqszmallFu8vSFsMAEO\n" +
            "jj9EHBeQImOCELiTjEBCmwdnxn6V/fHXQWAT9MclKuajukCNLY0CO+e/lXEv5CRd\n" +
            "rmAbDQl70Xy0Ebc0KTQcRiRjmHlhBULo9NwrAfQWbmZHssBQPb1jqYbzDGa4ut6P\n" +
            "IFwyllBAhrXUVgb5RbsjIzNMVHMJpovUHCOBrUXA2o9Bo+D5NPgCvW0nMXhEXq2G\n" +
            "H00AQwOA84e+0p0f5TSJ1VqLaGQVSXlNXgSClpmMiobQjyxerQI7JuKXKSkbErTU\n" +
            "Csi2S2fBAoGBAOkAsbFndMIoY+0QDsMjxAhDRSCnpZvbvS9i5LlNLUSb782NyMx3\n" +
            "TEeOaoySgk+REFIwwmvtdC46D+6vHrI49Ws52bx0h66eEiK/142xCc3CqJyi2ku6\n" +
            "rRqm/ff6N8fULstgdmoEwYv/jimd2dliYDtC6VYw1U+eE1tHLqjDWyQNAoGBAOP7\n" +
            "Q5aFEivH/YnCsTk9K21GZ9PnhzUmgRD48JXclygSkO+dY4Rkbft7IGt5oLNGe4jC\n" +
            "MwIpMI8cYjtIlH1pOwFrlnAf5oSgAZBGyRXOIOhwETLAJkBHtIncnY1Z/WdwK+EE\n" +
            "AfefX40y35T2ESwBWW5DKfv6BWlVUjbP/ZkGe3Z7AoGAXX5Kzs2dex7r4b7UvZaH\n" +
            "XW1ouo6qlBybD/2Vm4kNRf9wPMHMtcaU1A2gUWGkajriGqi4CsiQGtBvfi3Emmzi\n" +
            "hTEEXms/2mBRFKJ34sIMFgUq1Rc/kq2IMi6Zr7w2T7ejQzYkravU4dEcgTR2qpSf\n" +
            "2oehy1Ty8uySBclNPqiM1K0CgYEAyLOn8bfeolpisseKO4jFVWMY/q0iE8F8+FMf\n" +
            "gd7711RY8glN1fyP8keX5+XgelL/aAsG2s0mKabkN6qSxsFAJ+TuQHFk/7bZCYm3\n" +
            "dxHLWLVn/pS4V/iIUKG+tfTWKBzRFDvx+2v7s5Noz3u87E+XyoEoUeLupqdtREHg\n" +
            "0LmrMUcCgYEAxwV/SW1huPi/X3dgL/47FloPAVl8CUkN4xGDxnSX9htCi19m9Znm\n" +
            "RFywEvwfSFsbHesjiQ015M7f8ErTcg9KdYyVAs/Xd5Pt2saYKYkD6XFN7pQuqbz4\n" +
            "gTW0J4xI+jnZQjSbw0GG4Lx9Bunsg4tfaHoDZ4/fOfO6YMpA2wNUbx4=\n" +
            "-----END RSA PRIVATE KEY-----\n";
}
