package com.javadeveloperzone.repository;

import com.javadeveloperzone.models.User;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends MongoRepository<User,String> {
    User findByUsername(String userName);
    User findByEmail(String email);



}
