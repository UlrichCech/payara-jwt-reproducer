package de.test.platform.rest;

import org.eclipse.microprofile.auth.LoginConfig;

import javax.annotation.security.DeclareRoles;
import javax.enterprise.context.ApplicationScoped;
import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

/**
 * The JAX-RS configuration.
 *
 * @author Ulrich Cech
 */
@LoginConfig(authMethod = "MP-JWT", realmName = "MP-JWT")
@DeclareRoles({"ALL_USERS", "ADMIN"})
@ApplicationScoped
@ApplicationPath(RESTApplication.API_BASE_PATH)
public class RESTApplication extends Application {

    public static final String API_BASE_PATH = "/api"; // cannot be configurable, because of @ApplicationPath-Annotation

}
