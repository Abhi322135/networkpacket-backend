package com.javadeveloperzone.models;

import java.io.Serializable;

public class AuthenticationResponse implements Serializable {
    private final String jwt;
    private static final long serialVersionUID = -8091879091924046844L;
    public AuthenticationResponse(String jwt) {
        this.jwt = jwt;
    }

    public String getJwt() {
        return jwt;
    }
}
