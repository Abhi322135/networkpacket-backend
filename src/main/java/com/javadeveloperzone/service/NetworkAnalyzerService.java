package com.javadeveloperzone.service;

import com.javadeveloperzone.models.NetworkDeviceList;
import com.javadeveloperzone.models.PacketInfo;
import com.javadeveloperzone.models.TotalPacket;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.CompletableFuture;

public interface NetworkAnalyzerService {

    List <NetworkDeviceList> getDeviceList() throws IOException;

   CompletableFuture<String> save(int key,String token) throws IOException, NotOpenException, PcapNativeException;

    String stop() throws NotOpenException, PcapNativeException, IOException, InterruptedException;
   List<PacketInfo> findAll();
   List<PacketInfo> saveAllPacketBetweenTime(String date1,String date2,String email);
   List<TotalPacket> getAllPacketBetweenTime(String dateFrom,String dateTo);

}
