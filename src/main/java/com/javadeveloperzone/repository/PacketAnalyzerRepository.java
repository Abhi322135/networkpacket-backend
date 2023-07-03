package com.javadeveloperzone.repository;

import com.javadeveloperzone.models.PacketInfo;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface PacketAnalyzerRepository extends MongoRepository<PacketInfo,String> {
}
