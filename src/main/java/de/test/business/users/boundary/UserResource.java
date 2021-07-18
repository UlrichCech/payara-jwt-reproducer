package de.test.business.users.boundary;

import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.enterprise.context.RequestScoped;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;

/**
 * @author Ulrich Cech
 */
@Path("/")
@RequestScoped
public class UserResource {

    @GET
    @Produces("application/json")
    @PermitAll
    @Path("/v1/users/")
    public Response getUsers() {
        return Response.ok().build();
    }

    @GET
    @Produces("application/json")
    @RolesAllowed(value = {"ALL_USERS", "ADMIN"})
    @Path("/v1/users/{uid}")
    public Response getUserDetails(@PathParam("uid") String userId) {
        return Response.ok("userId=" + userId).build();
    }

}
