package com.javadeveloperzone.controller;

import com.javadeveloperzone.service.NetworkAnalyzerService;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
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
    public ResponseEntity<?> getNetworkDevices() throws IOException, PcapNativeException {
        return ResponseEntity.ok(networkAnalyzerService.getDeviceList());
    }

    @Secured("ROLE_ADMIN")
    @PostMapping ("/start/{key}")
    public ResponseEntity<?> startNetworkDevice(@PathVariable int key, HttpServletRequest request) throws NotOpenException, PcapNativeException, IOException {
        String jwtToken= networkAnalyzerService.resumeThread(request);
        return ResponseEntity.ok( networkAnalyzerService.save(key,jwtToken));
    }

    @Secured("ROLE_ADMIN")
    @PostMapping("/stop")
    public ResponseEntity<String> stopNetworkDevice(HttpServletRequest request) throws NotOpenException, PcapNativeException, IOException, InterruptedException {
        return ResponseEntity.ok(networkAnalyzerService.stop(request));
    }

    @Secured({"ROLE_ADMIN","ROLE_USER"})
    @GetMapping("/all/packet/info")
    public ResponseEntity<?> getAllPacketInfo(){
        return ResponseEntity.ok(networkAnalyzerService.findAll());
    }

    @Secured("ROLE_ADMIN")
    @PostMapping("/packets/between/time")
    public ResponseEntity<?> saveAllPacketInfo(@RequestBody List<String> information){
        return ResponseEntity.ok(networkAnalyzerService.saveAllPacketBetweenTime(information));
    }
    @PostMapping("number/of/packets/between/dates")
    public ResponseEntity<?> getNoOfPacketInBetweenDate(@RequestBody List<String> dates){
        return ResponseEntity.ok(networkAnalyzerService.getAllPacketBetweenTime(dates));
    }
}