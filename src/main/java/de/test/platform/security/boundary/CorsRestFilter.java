package de.test.platform.security.boundary;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ContainerResponseFilter;
import javax.ws.rs.container.PreMatching;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.ext.Provider;

@Provider
@PreMatching
public class CorsRestFilter extends AbstractCorsFilter implements ContainerResponseFilter {


    @Override
    public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) {
        final MultivaluedMap<String, Object> headers = responseContext.getHeaders();
        headers.add(HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN, "*");
//        headers.add(HTTP_HEADER_ACCESS_CONTROL_ALLOW_HEADERS, getRequestedAllowedHeaders(requestContext));
        headers.add(HTTP_HEADER_ACCESS_CONTROL_ALLOW_HEADERS, "*");
//        headers.add(HTTP_HEADER_ACCESS_CONTROL_EXPOSE_HEADERS, getRequestedExposedHeaders(requestContext));
        headers.add(HTTP_HEADER_ACCESS_CONTROL_EXPOSE_HEADERS, "*");
        headers.add(HTTP_HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
//        headers.add(HTTP_HEADER_ACCESS_CONTROL_ALLOW_METHODS, ALLOWED_METHODS);
        headers.add(HTTP_HEADER_ACCESS_CONTROL_ALLOW_METHODS, "*");
        headers.add(HTTP_HEADER_ACCESS_CONTROL_MAX_AGE, MAX_AGE_IN_SECONDS);
        headers.add(HTTP_HEADER_X_XSS_PROTECTION, "1; mode=block");
        headers.add(HTTP_HEADER_X_FRAME_OPTIONS, "sameorigin");
        headers.add(HTTP_HEADER_X_CONTENT_TYPE_OPTIONS, "nosniff");
    }

}