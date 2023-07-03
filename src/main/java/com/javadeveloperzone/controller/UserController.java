package com.javadeveloperzone.controller;

import com.javadeveloperzone.config.JwtTokenUtil;
import com.javadeveloperzone.models.AuthenticationRequest;
import com.javadeveloperzone.models.AuthenticationResponse;
import com.javadeveloperzone.models.Role;
import com.javadeveloperzone.models.User;
import com.javadeveloperzone.service.NetworkAnalyzerService;
import com.javadeveloperzone.service.UserAuthentication;
import com.javadeveloperzone.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.text.ParseException;
import java.util.List;

@RestController
public class UserController {

    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private UserAuthentication userAuthentication;
    @Autowired
    private JwtTokenUtil jwtTokenUtil;
    @Autowired
    private NetworkAnalyzerService networkAnalyzerService;
    @Autowired
    private UserService userService;

    @PostMapping("/authenticate/user")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception {
        authenticate(authenticationRequest.getUsername(), authenticationRequest.getPassword());
        final UserDetails userDetails= userAuthentication.loadUserByUsername(authenticationRequest.getUsername());
        final String jwt= jwtTokenUtil.generateToken(userDetails);
        return ResponseEntity.ok(new AuthenticationResponse(jwt));
    }
    private void authenticate(String username, String password) throws Exception {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        } catch (DisabledException e) {
            throw new Exception("USER_DISABLED", e);
        } catch (BadCredentialsException e) {
            throw new Exception("INVALID_CREDENTIALS", e);
        }catch (Exception e){
            throw new ResponseStatusException( HttpStatus.FORBIDDEN,"Incorrect Username or Password");
        }
    }
    @PostMapping("/user/creation")
    public void addUsers(@RequestBody User user) throws ParseException {
        ResponseEntity.ok(userService.createUser(user));
    }
    @Secured("ROLE_ADMIN")
    @PutMapping("/update/role")
    public void updateRoleOfUser(@RequestParam("username") String userName, @RequestBody List<Role> role)
    {
        ResponseEntity.ok(userService.updateUser(userName, role));

    }
}
