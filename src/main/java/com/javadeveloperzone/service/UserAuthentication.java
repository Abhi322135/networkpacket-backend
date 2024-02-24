package com.javadeveloperzone.service;

import com.javadeveloperzone.models.Role;
import com.javadeveloperzone.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
    public class UserAuthentication implements UserDetailsService {
      @Autowired
      UserRepository userRepository;

        @Override
        public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
            com.javadeveloperzone.models.User user=userRepository.findByUsername(userName);
            List<SimpleGrantedAuthority> roles;
            List<Role> roleList=user.getRole();
            if(roleList.contains(Role.ADMIN))
            {
                roles = List.of(new SimpleGrantedAuthority("ROLE_ADMIN"));
                return new User(user.getUsername(), user.getPassword(),roles);
            }
            else if(roleList.contains(Role.USER))
            {
                roles = List.of(new SimpleGrantedAuthority("ROLE_USER"));
                return new User(user.getUsername(), user.getPassword(),roles);
            }
            throw new UsernameNotFoundException("User not found with username: " + userName);
        }
    }