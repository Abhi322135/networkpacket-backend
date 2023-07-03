package com.javadeveloperzone.controller;


import com.javadeveloperzone.service.NetworkAnalyzerService;
import org.apache.commons.lang3.ThreadUtils;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Collections;
import java.util.List;

@RestController
@RequestMapping("/network/analyse")
public class NetworkAnalyzerController {
    @Autowired
    private NetworkAnalyzerService networkAnalyzerService;

    public NetworkAnalyzerController(NetworkAnalyzerService networkAnalyzerService) {
        this.networkAnalyzerService = networkAnalyzerService;
    }
    @Secured({"ROLE_ADMIN","ROLE_USER"})
    @GetMapping("/devices")
    public ResponseEntity<?> getNetworkDevices() throws IOException {
        return ResponseEntity.ok(networkAnalyzerService.getDeviceList());
    }
    @Secured("ROLE_ADMIN")
    @PostMapping ("/start/{key}")
    public ResponseEntity<?> startNetworkDevice(@PathVariable int key, HttpServletRequest request) throws NotOpenException, PcapNativeException, IOException {
        for (Thread t : ThreadUtils.getAllThreads()) {
            String thread=t.getName().toString();
            if(thread.equals("Abhi1"))
            {

                t.resume();
            }
         }
        String requestTokenHeader=request.getHeader("Authorization");
        String jwtToken=requestTokenHeader.substring(7);

        return ResponseEntity.ok( networkAnalyzerService.save(key,jwtToken));

    }
    @Secured("ROLE_ADMIN")
    @PostMapping("/stop")
    public ResponseEntity<String> stopNetworkDevice() throws NotOpenException, PcapNativeException, IOException, InterruptedException {
        return ResponseEntity.ok(networkAnalyzerService.stop());

    }
    @Secured({"ROLE_ADMIN","ROLE_USER"})
    @GetMapping("/all/packet/info")
    public ResponseEntity<?> getAllPacketInfo(){
        return ResponseEntity.ok(networkAnalyzerService.findAll());
    }
    @Secured("ROLE_ADMIN")
    @PostMapping("/packets/between/time")
    public ResponseEntity<?> saveAllPacketInfo(@RequestBody List<String> information){
        Collections.sort(information);
        String date1=information.get(0);
        String date2=information.get(1);
        String email="";
        if(information.size()==3)
            email=information.get(2);
        return ResponseEntity.ok(networkAnalyzerService.saveAllPacketBetweenTime(date1,date2,email));
    }
    @PostMapping("number/of/packets/between/dates")
    public ResponseEntity<?> getNoOfPacketInBetweenDate(@RequestBody List<String> dates){
        Collections.sort(dates);
        String dateFrom=dates.get(0);
        String dateTo=dates.get(1);
        return ResponseEntity.ok(networkAnalyzerService.getAllPacketBetweenTime(dateFrom,dateTo));
    }

}

