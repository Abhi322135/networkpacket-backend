package com.javadeveloperzone.service;

import com.javadeveloperzone.config.JwtTokenUtil;
import com.javadeveloperzone.models.NetworkDeviceList;
import com.javadeveloperzone.models.PacketInfo;
import com.javadeveloperzone.models.TotalPacket;
import com.javadeveloperzone.models.User;
import com.javadeveloperzone.repository.PacketAnalyzerRepository;
import com.javadeveloperzone.repository.UserRepository;
import org.apache.commons.lang3.ThreadUtils;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.ResolverStyle;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

@Service
public class NetworkAnalyzerServiceImpl implements NetworkAnalyzerService {
    PacketInfo packetInfo= null;
    int j = 1;
    @Autowired
    private PacketAnalyzerRepository packetAnalyzerRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    JwtTokenUtil jwtTokenUtil;
    public final MongoTemplate mongoTemplate;
    public  NetworkAnalyzerServiceImpl(MongoTemplate mongoTemplate){
        this.mongoTemplate=mongoTemplate;
    }
      @Override
    public List<NetworkDeviceList> getDeviceList() throws IOException {
        NetworkSelector nifSelector = new NetworkSelector();

        List<PcapNetworkInterface> listOfDevices = nifSelector.selectNetworkInterface();
        List<NetworkDeviceList> list1OfDevices = new ArrayList<NetworkDeviceList>();
        int c = 0;
        for (PcapNetworkInterface pcapNetworkInterface : listOfDevices) {
            c++;
            NetworkDeviceList networkDeviceList = new NetworkDeviceList(pcapNetworkInterface.getDescription(), pcapNetworkInterface.getName(), Collections.singletonList(pcapNetworkInterface.getLinkLayerAddresses().toString()), c,(pcapNetworkInterface.getAddresses().toString()));
            list1OfDevices.add(networkDeviceList);


        }
        return list1OfDevices;
    }


    @Override
    @Async("AsyncExecution")
    public CompletableFuture<String> save(int key,String token) throws NotOpenException, PcapNativeException {
        PcapNetworkInterface device = null;
        String username= jwtTokenUtil.getUsernameFromToken(token);
        User user= userRepository.findByUsername(username);
        String email=user.getEmail();

        // Pcap4j comes with a convenient method for listing
        // and choosing a network interface from the terminal
        try {
            // List the network devices available with a prompt
            device = new NifSelector().selectNetworkInterface(key);
        } catch (IOException e) {
            e.printStackTrace();
        }
        if (device == null) {
            System.out.println("No device chosen.");
            System.exit(1);
        }

        // Open the device and get a handle
        int snapshotLength = 65536; // in bytes
        int readTimeout = 60; // in milliseconds
        final PcapHandle handle;
        try {
            handle = device.openLive(snapshotLength, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, readTimeout);
        } catch (PcapNativeException e) {
            throw new RuntimeException(e);
        }
        PcapDumper dumper;
        try {
            dumper = handle.dumpOpen("out.pcap");
        } catch (PcapNativeException | NotOpenException e) {
            throw new RuntimeException(e);
        }
        // Set a filter to only listen for tcp packets on port 443 (HTTP)


        // Create a listener that defines what to do with the received packets
        PcapDumper finalDumper = dumper;
        PacketListener listener = new PacketListener() {
            @Override
            public void gotPacket(Packet packet) {
                // Print packet information to screen
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }

                try {

                    finalDumper.dump(packet, handle.getTimestamp());
                } catch (NotOpenException e) {
                    e.printStackTrace();
                }
                PacketContent packetContent=new PacketContent();
                try {
                     packetInfo=packetContent.extractPacketInfo(j,email);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
               if(packetInfo!=null)
               packetAnalyzerRepository.save(packetInfo);
                j++;
            }
        };

        // Tell the handle to loop using the listener we created
        try {
            int maxPackets = -1;
            handle.loop(maxPackets, listener);

        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        dumper.close();
        handle.close();
        return null;
    }

    @Override
    public String stop() {
        for (Thread t : ThreadUtils.getAllThreads()) {
            String thread=t.getName().toString();
            if(thread.equals("Abhi1"))
            {
                t.suspend();
            }
        }
         return "Device stopped";
    }
    @Override
    public List<PacketInfo> findAll()
    {
        return (packetAnalyzerRepository.findAll());
    }
    @Override
    public List<PacketInfo> saveAllPacketBetweenTime(String date1, String date2,String email){
        DateTimeFormatter dateTimeFormatter=DateTimeFormatter.ofPattern("uuuu.MM.dd.HH.mm.ss").withResolverStyle(ResolverStyle.STRICT);
        dateTimeFormatter.parse(date1);
        dateTimeFormatter.parse(date2);
        Query query = new Query();
        if(email=="")
        query.addCriteria(Criteria.where("timeStamp").lte(date2).gte(date1));
        else
            query.addCriteria(Criteria.where("timeStamp").lte(date2).gte(date1).and("email").is(email));
        return mongoTemplate.find(query,PacketInfo.class);
    }
    @Override
    public List<TotalPacket> getAllPacketBetweenTime(String dateFrom,String dateTo){
        DateTimeFormatter dateTimeFormatter=DateTimeFormatter.ofPattern("uuuu.MM.dd").withResolverStyle(ResolverStyle.STRICT);
        dateTimeFormatter.parse(dateFrom);
        dateTimeFormatter.parse(dateTo);
        LocalDate startDate= LocalDate.parse(dateFrom, dateTimeFormatter);
        LocalDate endDate=LocalDate.parse(dateTo, dateTimeFormatter);
        List<LocalDate> dates=startDate.datesUntil(endDate).collect(Collectors.toList());
        List<TotalPacket> totalPackets=new ArrayList<>();
        for(LocalDate date:dates){
            LocalDate nextDate=date.plusDays(1);
            String s=date.toString().replace('-','.').concat(".0.0.0");
            String s1=nextDate.toString().replace('-','.').concat(".0.0.0");
            Query query = new Query();
            query.addCriteria(Criteria.where("timeStamp").lt(s1).gte(s));
            int noOfPackets=mongoTemplate.find(query, PacketInfo.class).size();
            TotalPacket totalPacket=new TotalPacket();
            totalPacket.setDateFrom(date.toString());
            totalPacket.setNumberOfPackets(noOfPackets);
            totalPacket.setDateTo(date.plusDays(1).toString());
            totalPackets.add(totalPacket);
        }
        return totalPackets;
    }
}