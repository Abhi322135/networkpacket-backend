package com.javadeveloperzone.service;


import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import java.io.IOException;
import java.util.List;

public class NetworkSelector {

    private static String LINE_SEPARATOR = System.getProperty("line.separator");

    public final List<PcapNetworkInterface> selectNetworkInterface()throws IOException {
        List<PcapNetworkInterface> allDevs = null;
        try {
            allDevs = Pcaps.findAllDevs();
        } catch (PcapNativeException e) {
            throw new IOException(e.getMessage());
        }

        if (allDevs == null || allDevs.isEmpty()) {
            throw new IOException("No NIF to capture.");
        }

        return allDevs;
    }
}

