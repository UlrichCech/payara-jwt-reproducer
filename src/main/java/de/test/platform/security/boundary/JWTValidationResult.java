package de.test.platform.security.boundary;

/**
 * @author Ulrich Cech
 */
public class JWTValidationResult {

    private boolean verified;

    private boolean expired;

    private String subject;

    private String rawToken;

    public JWTValidationResult() {
    }

    public JWTValidationResult(boolean verified, boolean expired, String subject, String rawToken) {
        this.verified = verified;
        this.expired = expired;
        this.subject = subject;
        this.rawToken = rawToken;
    }

    public boolean isValid() {
        return verified && !expired;
    }

    public boolean isVerified() {
        return verified;
    }

    public boolean isExpired() {
        return expired;
    }

    public String getSubject() {
        return subject;
    }

    public String getRawToken() {
        return rawToken;
    }
}
