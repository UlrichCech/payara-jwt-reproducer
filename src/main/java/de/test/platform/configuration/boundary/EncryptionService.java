package de.test.platform.configuration.boundary;

import javax.annotation.PostConstruct;
import javax.ejb.Singleton;
import javax.ejb.Startup;
import java.io.Serializable;

/**
 * @author Ulrich Cech
 */
@Startup
@Singleton
public class EncryptionService implements Serializable {
    private static final long serialVersionUID = 4475950614666760884L;


    public EncryptionService() {
        System.out.println("EncryptionService constructor called.");
    }

    @PostConstruct
    public void init() {
        System.out.println("EncryptionService#init(PostConstruct) called.");
    }

    public String encrypt(String value) {
        return "FAKE_ENCRYPTION..." + value + "...---";
    }

}
