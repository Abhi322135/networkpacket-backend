package com.javadeveloperzone.service;

import com.javadeveloperzone.config.JwtTokenUtil;
import com.javadeveloperzone.models.AuthenticationRequest;
import com.javadeveloperzone.models.AuthenticationResponse;
import com.javadeveloperzone.models.Role;
import com.javadeveloperzone.models.User;
import com.javadeveloperzone.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.format.DateTimeFormatter;
import java.time.format.ResolverStyle;
import java.util.List;

@Service
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenUtil jwtTokenUtil;
    private final AuthenticationManager authenticationManager;
    private final UserAuthentication userAuthentication;
    @Autowired
    public UserServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtTokenUtil jwtTokenUtil, AuthenticationManager authenticationManager, UserAuthentication userAuthentication) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenUtil = jwtTokenUtil;
        this.authenticationManager = authenticationManager;
        this.userAuthentication = userAuthentication;
    }

    @Override
    public User createUser(User user) {
        DateTimeFormatter dateTimeFormatter=DateTimeFormatter.ofPattern("dd/MM/uuuu").withResolverStyle(ResolverStyle.STRICT);
        dateTimeFormatter.parse(user.getDateOfBirth());
       List< User> userList=userRepository.findAll();

        if (userList.stream().anyMatch(u -> u.getUsername().equals(user.getUsername()) || u.getEmail().equals(user.getEmail()))) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "UserName or Email Already Exist");
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);

    }
    @Override
    public User updateUser(String userName, List<Role> role)
    {
        try {
            User user=userRepository.findByUsername(userName);
            user.setRole(role);
            return userRepository.save(user);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public AuthenticationResponse authenticateUser(AuthenticationRequest authenticationRequest) throws Exception {
        authenticate(authenticationRequest.getUsername(),authenticationRequest.getPassword());
        final UserDetails userDetails= userAuthentication.loadUserByUsername(authenticationRequest.getUsername());
        final String jwt= jwtTokenUtil.generateToken(userDetails);
        return (new AuthenticationResponse(jwt));
    }
    private void authenticate(String username, String password) throws Exception {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        } catch (DisabledException e) {
            throw new Exception("USER_DISABLED", e);
        } catch (BadCredentialsException e) {
            throw new Exception("INVALID_CREDENTIALS", e);
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Incorrect Username or Password");
        }
    }

}
