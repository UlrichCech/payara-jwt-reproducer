package de.test.platform.security.boundary;

import javax.json.Json;
import javax.json.JsonWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * @author Ulrich Cech
 */
public class MPJWTToken {
    private String iss;
    private String aud;
    private String jti;
    private Long exp;
    private Long iat;
    private String sub;
    private String upn;
    private List<String> groups = new ArrayList<>();
    private List<String> roles;
    private Map<String, String> additionalClaims;


    public String toJSONString() {
        final var jsonObjectBuilder = Json.createObjectBuilder()
                .add("iss", iss)
                .add("aud", aud)
                .add("jti", jti)
                .add("exp", exp / 1000)
                .add("iat", iat / 1000)
                .add("sub", sub)
                .add("upn", upn);
        if (additionalClaims != null) {
            for (Map.Entry<String, String> entry : additionalClaims.entrySet()) {
                jsonObjectBuilder.add(entry.getKey(), entry.getValue());
            }
        }
        final var jsonArrayBuilder = Json.createArrayBuilder();
        for (String group : groups) {
            jsonArrayBuilder.add(group);
        }
        jsonObjectBuilder.add("groups", jsonArrayBuilder);
        var stringWriter = new StringWriter();
        try (JsonWriter writer = Json.createWriter(stringWriter)) {
            writer.writeObject(jsonObjectBuilder.build());
            return stringWriter.toString();
        }
    }


    public String getIss() {
        return iss;
    }

    public void setIss(String iss) {
        this.iss = iss;
    }

    public String getAud() {
        return aud;
    }

    public void setAud(String aud) {
        this.aud = aud;
    }

    public String getJti() {
        return jti;
    }

    public void setJti(String jti) {
        this.jti = jti;
    }

    public Long getExp() {
        return exp;
    }

    public void setExp(Long exp) {
        this.exp = exp;
    }

    public Long getIat() {
        return iat;
    }

    public void setIat(Long iat) {
        this.iat = iat;
    }

    public String getSub() {
        return sub;
    }

    public void setSub(String sub) {
        this.sub = sub;
    }

    public String getUpn() {
        return upn;
    }

    public void setUpn(String upn) {
        this.upn = upn;
    }

    public List<String> getGroups() {
        return groups;
    }

    public void setGroups(List<String> groups) {
        this.groups = groups;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }

    public Map<String, String> getAdditionalClaims() {
        return additionalClaims;
    }

    public void setAdditionalClaims(Map<String, String> additionalClaims) {
        this.additionalClaims = additionalClaims;
    }
}