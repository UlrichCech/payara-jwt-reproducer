package de.test.platform.security.boundary;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * @author Ulrich Cech
 */
public abstract class AbstractCorsFilter {

    protected static final String ALLOWED_METHODS = "GET, POST, PUT, DELETE, OPTIONS, HEAD";
    protected static final int MAX_AGE_IN_SECONDS = 24 * 60 * 60; // one day
    static final List<String> DEFAULT_ALLOWED_HEADERS = Arrays.asList("origin", "accept", "content-type", "Authorization", "x-request-id", "refresh_token", "sentry-trace");
    static final List<String> DEFAULT_EXPOSED_HEADERS = Arrays.asList("Location", "info", "Authorization", "refresh_token", "sentry-trace");

    public static final String HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN = "Access-Control-Allow-Origin";
    public static final String HTTP_HEADER_ACCESS_CONTROL_ALLOW_HEADERS = "Access-Control-Allow-Headers";
    public static final String HTTP_HEADER_ACCESS_CONTROL_EXPOSE_HEADERS = "Access-Control-Expose-Headers";
    public static final String HTTP_HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS = "Access-Control-Allow-Credentials";
    public static final String HTTP_HEADER_ACCESS_CONTROL_ALLOW_METHODS = "Access-Control-Allow-Methods";
    public static final String HTTP_HEADER_ACCESS_CONTROL_MAX_AGE = "Access-Control-Max-Age";
    public static final String HTTP_HEADER_X_XSS_PROTECTION = "X-XSS-Protection";
    public static final String HTTP_HEADER_X_FRAME_OPTIONS = "X-Frame-Options";
    public static final String HTTP_HEADER_X_CONTENT_TYPE_OPTIONS = "X-Content-Type-Options";


    protected String createHeaderList(List<String> headers, List<String> defaultHeaders) {
        List<String> resultHeaders = new ArrayList<>();
        if (headers == null || headers.isEmpty()) {
            return String.join(", ", defaultHeaders);
        } else {
            for (String header : headers) {
                final String[] strings = header.split(", ");
                Collections.addAll(resultHeaders, strings);
            }
        }
        for (String defaultHeader : defaultHeaders) {
            if (! resultHeaders.contains(defaultHeader)) {
                resultHeaders.add(defaultHeader);
            }
        }
        return String.join(", ", resultHeaders);
    }

}
