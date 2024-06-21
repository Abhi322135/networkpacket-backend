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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.FileWriter;
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
    List<PacketInfo> packetInfo= new ArrayList<>();
    @Autowired
    private PacketAnalyzerRepository packetAnalyzerRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    JwtTokenUtil jwtTokenUtil;
    PcapHandle handle;
    PcapDumper dumper;
    public final MongoTemplate mongoTemplate;
    public  NetworkAnalyzerServiceImpl(MongoTemplate mongoTemplate){
        this.mongoTemplate=mongoTemplate;
    }
    @Override
    public List<NetworkDeviceList> getDeviceList() throws IOException, PcapNativeException {
        List<PcapNetworkInterface> listOfDevices = Pcaps.findAllDevs();
        List<NetworkDeviceList> list1OfDevices = new ArrayList<>();
        return fetchDeviceInfo(listOfDevices,list1OfDevices);
    }
    @Override
    @Async("AsyncExecution")
    public CompletableFuture<String> save(int key, String token) throws NotOpenException, PcapNativeException {
        List<PcapNetworkInterface> listOfDevices = Pcaps.findAllDevs();
        PcapNetworkInterface device=selectDevice(key,listOfDevices);
        if (device == null) {
            System.out.println("No device chosen.");
            System.exit(1);
        }

        int snapshotLength = 65536; // in bytes
        int readTimeout = 60; // in milliseconds
        try {
            handle = device.openLive(snapshotLength, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, readTimeout);
            String filter = "port 443";
            handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);
        } catch (PcapNativeException e) {
            throw new RuntimeException(e);
        }
        try {
            dumper = handle.dumpOpen("out.pcap");
        } catch (PcapNativeException | NotOpenException e) {
            throw new RuntimeException(e);
        }
        PcapDumper finalDumper = dumper;
        PacketListener listener = packet -> {
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
        };
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
    public String stop(HttpServletRequest request) {
        ThreadUtils.getAllThreads().stream()
                .filter(t -> t.getName().equals("Abhi1"))
                .findFirst()
                .ifPresent(Thread::suspend);
         String jwtToken=getJWTTocken(request);
         storePacket(jwtToken);
         return "Device stopped";
    }
    @Override
    public List<PacketInfo> findAll()
    {
        return (packetAnalyzerRepository.findAll());
    }
    @Override
    public List<PacketInfo> saveAllPacketBetweenTime(List<String> information){
        Collections.sort(information);
        String date1=information.get(0);
        String date2=information.get(1);
        String email="";
        if(information.size()==3)
            email=information.get(2);
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
    public List<TotalPacket> getAllPacketBetweenTime(List<String> listOfDates){
        Collections.sort(listOfDates);
        String dateFrom=listOfDates.get(0);
        String dateTo=listOfDates.get(1);
        DateTimeFormatter dateTimeFormatter=DateTimeFormatter.ofPattern("uuuu.MM.dd").withResolverStyle(ResolverStyle.STRICT);
        dateTimeFormatter.parse(dateFrom);
        dateTimeFormatter.parse(dateTo);
        LocalDate startDate= LocalDate.parse(dateFrom, dateTimeFormatter);
        LocalDate endDate=LocalDate.parse(dateTo, dateTimeFormatter);
        List<LocalDate> dates=startDate.datesUntil(endDate).collect(Collectors.toList());
        return getTotalPackets(dates);
    }

    @Override
    public String resumeThread(HttpServletRequest request) {

        ThreadUtils.getAllThreads().stream()
                .filter(t -> t.getName().equals("Abhi1"))
                .findFirst()
                .ifPresent(Thread::resume);
        return getJWTTocken(request);
    }
    private void storePacket(String jwtToken)  {
        String username= jwtTokenUtil.getUsernameFromToken(jwtToken);
        User user= userRepository.findByUsername(username);
        String email=user.getEmail();
        PacketContent packetContent=new PacketContent();
        try {
            packetInfo=packetContent.extractPacketInfo(email);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        if(packetInfo!=null)
            packetAnalyzerRepository.saveAll(packetInfo);
        flushFile();
    }

    private void flushFile() {
        File f=new File("out.pcap");
        try {
            FileWriter fileWriter=new FileWriter(f);
            fileWriter.write("");
            fileWriter.flush();
            fileWriter.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private String getJWTTocken(HttpServletRequest request) {
        String requestTokenHeader=request.getHeader("Authorization");
        return requestTokenHeader.substring(7);
    }

    private PcapNetworkInterface selectDevice(int key, List<PcapNetworkInterface> nifs) {
        int nifIdx;
        int input=key-1;
        try {
            nifIdx = input;
            if (nifIdx < 0 || nifIdx >= nifs.size()) {
                throw new RuntimeException("Invalid input as the index is greater than number of device");
            }
        } catch (NumberFormatException e) {
            throw new RuntimeException("Invalid input");
        }
        return nifs.get(nifIdx);
    }

    private List<TotalPacket> getTotalPackets(List<LocalDate> dates) {
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

    private List<NetworkDeviceList> fetchDeviceInfo(List<PcapNetworkInterface> listOfDevices,List<NetworkDeviceList> list1OfDevices) {
        int c = 0;
        for (PcapNetworkInterface pcapNetworkInterface : listOfDevices) {
            c++;
            NetworkDeviceList networkDeviceList = new NetworkDeviceList(pcapNetworkInterface.getDescription(), pcapNetworkInterface.getName(), Collections.singletonList(pcapNetworkInterface.getLinkLayerAddresses().toString()), c,(pcapNetworkInterface.getAddresses().toString()));
            list1OfDevices.add(networkDeviceList);
        }

        return list1OfDevices;
    }
}