package com.javadeveloperzone.service;

import com.javadeveloperzone.models.PacketInfo;
import io.pkts.Pcap;
import io.pkts.packet.IPv4Packet;
import io.pkts.packet.IPv6Packet;
import io.pkts.packet.TCPPacket;
import io.pkts.packet.UDPPacket;
import io.pkts.protocol.Protocol;

import java.io.*;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;

public class PacketContent {
    PacketInfo packetInfo = null;
    List<PacketInfo> list;
    public PacketContent() {
        list=new ArrayList<>();
    }
     public List<PacketInfo> extractPacketInfo(String email) throws IOException {
        final String filename = "out.pcap";
        final InputStream stream = new FileInputStream(filename);
        final Pcap pcap = Pcap.openStream(stream);
        pcap.loop(packet -> {
                if (packet.hasProtocol(Protocol.TCP) && packet.hasProtocol(Protocol.IPv4) ) {
                    TCPPacket tcpPacket = (TCPPacket) packet.getPacket(Protocol.TCP);
                    IPv4Packet ipv4Packet = (IPv4Packet) packet.getPacket(Protocol.IPv4);

                    String payload;
                    try {
                        payload = tcpPacket.getPayload().toString();
                    } catch (Exception e) {
                        payload = "null";
                    }

                    String sourceIP;
                    String destinationIP;
                    try {
                        sourceIP=ipv4Packet.getSourceIP();
                    } catch (Exception e) {
                        sourceIP="null";
                    }
                    try {
                        destinationIP=ipv4Packet.getDestinationIP();
                    } catch (Exception e) {
                        destinationIP="null";
                    }
                    String timeStamp=new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new java.util.Date());
                    packetInfo = new PacketInfo(tcpPacket.getDestinationPort(), tcpPacket.getSourcePort(), payload,sourceIP,destinationIP,timeStamp,email,ipv4Packet.getTotalIPLength());
                }
                else if (packet.hasProtocol(Protocol.TCP) && packet.hasProtocol(Protocol.IPv6) ) {
                    TCPPacket tcpPacket = (TCPPacket) packet.getPacket(Protocol.TCP);
                    IPv6Packet ipv6Packet = (IPv6Packet) packet.getPacket(Protocol.IPv6);

                    String payload;
                    try {
                        payload = tcpPacket.getPayload().toString();
                    } catch (Exception e) {
                        payload = "null";
                    }
                    String sourceIP;
                    String destinationIP;
                    try {
                        sourceIP=ipv6Packet.getSourceIP();
                    } catch (Exception e) {
                        sourceIP="null";
                    }
                    try {
                        destinationIP=ipv6Packet.getDestinationIP();
                    } catch (Exception e) {
                        destinationIP="null";
                    }
                    String timeStamp=new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new java.util.Date());
                    packetInfo = new PacketInfo(tcpPacket.getDestinationPort(), tcpPacket.getSourcePort(), payload,sourceIP,destinationIP,timeStamp,email, ipv6Packet.getTotalIPLength());
                }

                else if (packet.hasProtocol(Protocol.UDP) && packet.hasProtocol(Protocol.IPv4)) {
                    UDPPacket udpPacket = (UDPPacket) packet.getPacket(Protocol.UDP);
                    IPv4Packet ipv4Packet = (IPv4Packet) packet.getPacket(Protocol.IPv4);
                    String payload;
                    try {
                        payload = udpPacket.getPayload().toString();
                    } catch (Exception e) {
                        payload = "null";
                    }

                    String sourceIP;
                    String destinationIP;
                    try {
                        sourceIP=ipv4Packet.getSourceIP();
                    } catch (Exception e) {
                        sourceIP="null";
                    }
                    try {
                        destinationIP=ipv4Packet.getDestinationIP();
                    } catch (Exception e) {
                        destinationIP="null";
                    }
                    String timeStamp=new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new java.util.Date());
                    packetInfo = new PacketInfo(udpPacket.getDestinationPort(), udpPacket.getSourcePort(), payload,sourceIP,destinationIP,timeStamp,email, ipv4Packet.getTotalIPLength());
                }
                else if (packet.hasProtocol(Protocol.UDP) && packet.hasProtocol(Protocol.IPv6)) {
                    UDPPacket udpPacket = (UDPPacket) packet.getPacket(Protocol.UDP);
                    IPv6Packet ipv6Packet = (IPv6Packet) packet.getPacket(Protocol.IPv6);
                    String payload;
                    try {
                        payload = udpPacket.getPayload().toString();
                    } catch (Exception e) {
                        payload = "null";
                    }
                    String sourceIP;
                    String destinationIP;
                    try {
                        sourceIP=ipv6Packet.getSourceIP();
                    } catch (Exception e) {
                        sourceIP="null";
                    }
                    try {
                        destinationIP=ipv6Packet.getDestinationIP();
                    } catch (Exception e) {
                        destinationIP="null";
                    }
                    String timeStamp=new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new java.util.Date());
                    packetInfo = new PacketInfo(udpPacket.getDestinationPort(), udpPacket.getSourcePort(), payload,sourceIP,destinationIP,timeStamp,email, ipv6Packet.getTotalIPLength());
                }

                else if(packet.hasProtocol(Protocol.IPv6))
                {
                    IPv6Packet iPv6Packet=(IPv6Packet)packet.getPacket(Protocol.IPv6);
                    String payload;
                    try {
                        payload = iPv6Packet.getPayload().toString();
                    } catch (Exception e) {
                        payload = "null";
                    }
                    String sourceIP;
                    String destinationIP;
                    try {
                        sourceIP=iPv6Packet.getSourceIP();
                    } catch (Exception e) {
                        sourceIP="null";
                    }
                    try {
                        destinationIP=iPv6Packet.getDestinationIP();
                    } catch (Exception e) {
                        destinationIP="null";
                    }
                    String timeStamp=new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new java.util.Date());
                    packetInfo=new PacketInfo(0,0,payload,sourceIP,destinationIP,timeStamp,email, iPv6Packet.getTotalIPLength());
                }
                else if(packet.hasProtocol(Protocol.IPv4))
                {
                    IPv4Packet iPv4Packet=(IPv4Packet)packet.getPacket(Protocol.IPv4);
                    String payload;
                    try {
                        payload = iPv4Packet.getPayload().toString();
                    } catch (Exception e) {
                        payload = "null";
                    }
                    String sourceIP;
                    String destinationIP;
                    try {
                        sourceIP=iPv4Packet.getSourceIP();
                    } catch (Exception e) {
                        sourceIP="null";
                    }
                    try {
                        destinationIP=iPv4Packet.getDestinationIP();
                    } catch (Exception e) {
                        destinationIP="null";
                    }

                    String timeStamp=new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new java.util.Date());
                    packetInfo=new PacketInfo(0,0,payload,sourceIP,destinationIP,timeStamp,email, iPv4Packet.getTotalIPLength());
                }
            list.add(packetInfo);
            return true;
        });
        try {
            System.err.println("Capture Complete");
            return list;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}