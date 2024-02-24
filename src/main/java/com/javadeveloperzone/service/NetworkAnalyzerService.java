package com.javadeveloperzone.service;

import com.javadeveloperzone.models.NetworkDeviceList;
import com.javadeveloperzone.models.PacketInfo;
import com.javadeveloperzone.models.TotalPacket;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.List;
import java.util.concurrent.CompletableFuture;

public interface NetworkAnalyzerService {

    List <NetworkDeviceList> getDeviceList() throws IOException, PcapNativeException;

   CompletableFuture<String> save(int key,String token) throws IOException, NotOpenException, PcapNativeException;

    String stop(HttpServletRequest request) throws NotOpenException, PcapNativeException, IOException, InterruptedException;
   List<PacketInfo> findAll();
   List<PacketInfo> saveAllPacketBetweenTime(List<String> information);
   List<TotalPacket> getAllPacketBetweenTime(List<String> listOfDates);
   String resumeThread(HttpServletRequest request);

}
