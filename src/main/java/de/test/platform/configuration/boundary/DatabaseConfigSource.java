package de.test.platform.configuration.boundary;

import org.eclipse.microprofile.config.spi.ConfigSource;

import javax.annotation.PostConstruct;
import javax.ejb.*;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * @author Ulrich Cech
 */
@Startup
@LocalBean
@Singleton
@DependsOn("EncryptionService")
public class DatabaseConfigSource implements ConfigSource {

    public static final String NAME = "DatabaseConfigSource";

    private static Map<String, String> properties = null;


    @EJB
    DatabaseConfigWorker databaseConfigWorker;


    public DatabaseConfigSource() {
        properties = new HashMap<>();
        System.out.println("DatabaseConfigSource constructor called");
    }



    /**
     * ATTENTION: Payara PublicKeyStore updates 5 minutes after start with the DatabaseConfigSource-values
     */
    @PostConstruct
    void init() {
        System.out.println("DatabaseConfigSource#init(PostConstruct) called");
        System.out.println(databaseConfigWorker.readConfigFromDatabase());
    }


    @Schedule(hour = "*", minute = "*", second = "*/10", persistent = false)
    public void refreshConfigValuesFromDatabase() {
        System.out.println(databaseConfigWorker.readConfigFromDatabase());
    }




    @Override
    public int getOrdinal() {
        return 900; // the config values from database should always 'win'
    }

    @Override
    public String getValue(String key) {
        System.out.println("DatabaseConfigSource#getValue(), key=" + key + " was called.");
        if (properties != null) {
            return properties.get(key);
        } else {
            return null;
        }
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public Map<String, String> getProperties() {
        return properties;
    }

    @Override
    public Set<String> getPropertyNames() {
        return properties.keySet();
    }
}
