package com.javadeveloperzone.service;

import com.javadeveloperzone.models.AuthenticationRequest;
import com.javadeveloperzone.models.AuthenticationResponse;
import com.javadeveloperzone.models.Role;
import com.javadeveloperzone.models.User;

import java.text.ParseException;
import java.util.List;

public interface UserService {
    User createUser(User user) throws ParseException;
    User updateUser(String username, List<Role> role);
    AuthenticationResponse authenticateUser(AuthenticationRequest authenticationRequest) throws Exception;
}
