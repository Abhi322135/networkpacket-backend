package com.javadeveloperzone.models;

import java.io.Serializable;

public class AuthenticationRequest implements Serializable {
    private String username;
    private String password;
    private static final long serialVersionUID = 5926468583005150707L;

    public AuthenticationRequest(String username, String password) {
        this.username = username;
        this.password = password;
    }
    public AuthenticationRequest() {
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}

