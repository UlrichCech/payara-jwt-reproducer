package de.test.platform.configuration.boundary;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import java.io.Serializable;

/**
 * @author Ulrich Cech
 */
@Stateless
public class DatabaseConfigWorker implements Serializable {

    private static final long serialVersionUID = 835254115604607359L;


    @EJB
    EncryptionService encryptionService;

    public DatabaseConfigWorker() {
        System.out.println("DatabaseConfigWorker constructor called");
    }

    @PostConstruct
    public void init() {
        System.out.println("DatabaseConfigWorker#init(PostConstruct) called");
    }

    public String readConfigFromDatabase() {
        System.out.println(encryptionService.encrypt("HELLO-FROM-CONFIGWORKER"));
        return "configuration from database was read successful.";
    }

}
