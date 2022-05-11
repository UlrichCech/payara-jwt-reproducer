package de.test.platform.security.boundary;

import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Enumeration;
import java.util.logging.Logger;

import static java.util.logging.Logger.getLogger;

/**
 * @author Ulrich Cech
 */
@WebFilter(filterName = "CorsWebFilter", value = "/*", asyncSupported = true)
public class CorsWebFilter extends AbstractCorsFilter implements Filter {

    private static final Logger LOG = getLogger(CorsWebFilter.class.getName());


    @Override
    public void init(FilterConfig fConfig) throws ServletException {
        ServletContext context = fConfig.getServletContext();
        context.log("GlobalSecurityFilter initialized");
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        var httpServletRequest = (HttpServletRequest) request;
        var httpServletResponse = (HttpServletResponse) response;
        if (httpServletRequest.getMethod().equalsIgnoreCase("get")) {
            System.out.println("");
        }
        LOG.info(getLogMessage (httpServletRequest));
        chain.doFilter(request, response);
        System.out.println();
        httpServletResponse.addHeader(HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN, "*");
        httpServletResponse.addHeader(HTTP_HEADER_ACCESS_CONTROL_ALLOW_HEADERS, "*");
        httpServletResponse.addHeader(HTTP_HEADER_ACCESS_CONTROL_EXPOSE_HEADERS, "*");
        httpServletResponse.addHeader(HTTP_HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
        httpServletResponse.addHeader(HTTP_HEADER_ACCESS_CONTROL_ALLOW_METHODS, "*");
        httpServletResponse.addHeader(HTTP_HEADER_ACCESS_CONTROL_MAX_AGE, String.valueOf(MAX_AGE_IN_SECONDS));
        httpServletResponse.addHeader(HTTP_HEADER_X_XSS_PROTECTION, "1; mode=block");
        httpServletResponse.addHeader(HTTP_HEADER_X_FRAME_OPTIONS, "sameorigin");
        httpServletResponse.addHeader(HTTP_HEADER_X_CONTENT_TYPE_OPTIONS, "nosniff");
    }

    @Override
    public void destroy() {
        //close any resources here
    }

//    String getRequestedAllowedHeaders(HttpServletRequest httpServletRequest) {
//        final Enumeration<String> headers = httpServletRequest.getHeaders("Access-Control-Allow-Headers");
//        return createHeaderList(convertEnumerationToList(headers), DEFAULT_ALLOWED_HEADERS);
//    }
//
//    String getRequestedExposedHeaders(HttpServletRequest httpServletRequest) {
//        Enumeration<String> headers = httpServletRequest.getHeaders("Access-Control-Expose-Headers");
//        return createHeaderList(convertEnumerationToList(headers), DEFAULT_EXPOSED_HEADERS);
//    }

//    private List<String> convertEnumerationToList(Enumeration<String> enumeration) {
//        List<String> v = new ArrayList<>();
//        if (enumeration != null) {
//            while (enumeration.hasMoreElements()) {
//                v.add(enumeration.nextElement());
//            }
//        }
//        return v;
//    }


    private String getLogMessage(HttpServletRequest request) {
        return "HTTP-Method=" + request.getMethod() + ", contextPath=" + request.getContextPath()
                + ", requestURI=" + request.getRequestURI() + ", queryString=" + request.getQueryString()
                + ", remoteServer=" + request.getRemoteAddr() + "##" + request.getRemoteHost()
                + ", headers=[" + getHeaders(request) + "]";
    }

    private String getHeaders(HttpServletRequest request) {
        StringBuilder sb = new StringBuilder();
        final Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            sb.append(headerName).append("=").append(request.getHeader(headerName));
        }
        return sb.toString();
    }

}
