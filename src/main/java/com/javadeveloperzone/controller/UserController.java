package com.javadeveloperzone.controller;

import com.javadeveloperzone.models.AuthenticationRequest;
import com.javadeveloperzone.models.Role;
import com.javadeveloperzone.models.User;
import com.javadeveloperzone.service.NetworkAnalyzerService;
import com.javadeveloperzone.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.*;

import java.text.ParseException;
import java.util.List;

@RestController
public class UserController {

    @Autowired
    private NetworkAnalyzerService networkAnalyzerService;
    @Autowired
    private UserService userService;

    @PostMapping("/authenticate/user")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception {
        return ResponseEntity.ok(userService.authenticateUser(authenticationRequest));
    }

  @Secured("ROLE_ADMIN")
    @PostMapping("/user/creation")
    public void addUsers(@RequestBody User user) throws ParseException {
        ResponseEntity.ok(userService.createUser(user));
    }
    @Secured("ROLE_ADMIN")
    @PutMapping("/update/role")
    public void updateRoleOfUser(@RequestParam("username") String userName, @RequestBody List<Role> role){
        ResponseEntity.ok(userService.updateUser(userName, role));
    }
}
