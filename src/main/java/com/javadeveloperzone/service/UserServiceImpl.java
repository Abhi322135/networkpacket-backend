package com.javadeveloperzone.service;

import com.javadeveloperzone.models.Role;
import com.javadeveloperzone.models.User;
import com.javadeveloperzone.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.format.DateTimeFormatter;
import java.time.format.ResolverStyle;
import java.util.List;

@Service
public class UserServiceImpl implements UserService {
    @Autowired
    private UserRepository userRepository;
    @Override
    public User createUser(User user) {
        DateTimeFormatter dateTimeFormatter=DateTimeFormatter.ofPattern("dd/MM/uuuu").withResolverStyle(ResolverStyle.STRICT);
        dateTimeFormatter.parse(user.getDateOfBirth());
       List< User> userList=userRepository.findAll();
        for(User user1:userList)
        {
            if((user1.getUsername()).equals(user.getUsername()) || (user1.getEmail()).equals(user.getEmail()))
                throw new ResponseStatusException( HttpStatus.BAD_REQUEST,"UserName or Email Already Exist");
        }
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

}
