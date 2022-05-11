package de.test.platform.security.boundary;

import de.test.platform.StringUtils;

import javax.annotation.PostConstruct;
import javax.annotation.Priority;
import javax.ejb.EJB;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * @author Ulrich Cech
 */
@Provider
@Priority(Priorities.AUTHENTICATION)
public class AuthenticationFilter implements ContainerRequestFilter {

    private static final String REALM_SCHEMA = "<jwt-token>";
    private static final String AUTHENTICATION_SCHEME = "Bearer";

    private final List<String> excludePathList = new ArrayList<>();


    @EJB
    JWTTokenService tokenService;

    @PostConstruct
    private void init() {
        excludePathList.add("/api/openapi-ui/index.html");
        excludePathList.add("/api/openapi-ui/style.css");
        excludePathList.add("/api/openapi-ui/logo.png");

    }


    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        // handle preflight requests
        if (requestContext.getMethod().equals("OPTIONS")) {
            return;
        }
        if (isExcludedUrl(requestContext)) {
            return;
        }
        // Get the Authorization header from the request
        var authorizationHeader = requestContext.getHeaderString(HttpHeaders.AUTHORIZATION);
        // Validate the Authorization header
        if (! isTokenBasedAuthentication(authorizationHeader)) {
            abortWithUnauthorized(requestContext);
            return;
        }
        // Extract the token from the Authorization header
        String token = authorizationHeader
                .substring(AUTHENTICATION_SCHEME.length()).trim();
        try {
            // Validate the token
            validateToken(token, requestContext);
        } catch (Exception e) {
            abortWithUnauthorized(requestContext);
        }
    }

    private boolean isExcludedUrl(ContainerRequestContext requestContext) {
        var requestPath = ensureNoTrailingSpace(requestContext.getUriInfo().getRequestUri().getPath());
        for (String exclude : excludePathList) {
            if (requestPath.equals(exclude)) {
                return true;
            }
        }
        return false;
    }

    String ensureNoTrailingSpace(String path) {
        if (StringUtils.isNotBlank(path) && (path.endsWith("/"))) {
            path = path.substring(0, path.length() - 1);
        }
        return path;
    }

    private boolean isTokenBasedAuthentication(String authorizationHeader) {
        // Check if the Authorization header is valid
        // It must not be null and must be prefixed with "Bearer" plus a whitespace
        // The authentication scheme comparison must be case-insensitive
        return authorizationHeader != null && authorizationHeader.toLowerCase()
                .startsWith(AUTHENTICATION_SCHEME.toLowerCase() + " ");
    }

    private void abortWithUnauthorized(ContainerRequestContext requestContext) {
        // Abort the filter chain with a 401 status code response
        // The WWW-Authenticate header is sent along with the response
        requestContext.abortWith(
                Response.status(Response.Status.UNAUTHORIZED)
                        .header(HttpHeaders.WWW_AUTHENTICATE,
                                AUTHENTICATION_SCHEME + " realm=\"" + REALM_SCHEMA + "\"")
                        .entity("Fehler!")
                        .build());
    }

    private void validateToken(String token, ContainerRequestContext requestContext) {
        final Optional<JWTValidationResult> jwtValidationResult = tokenService.validateToken(token);
        if (jwtValidationResult.isPresent() && (jwtValidationResult.get().isValid())) {
            // IMPORTANT: check, if the Token is still attached to the user!!!
            String externalUserLoginId = jwtValidationResult.get().getSubject();
            try {
                System.out.println("Success... token belongs to user");
            } catch (Exception apiex) {
                abortWithUnauthorized(requestContext);
            }
        } else {
            abortWithUnauthorized(requestContext);
        }
    }
}
