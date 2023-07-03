package com.javadeveloperzone.service;

import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.util.LinkLayerAddress;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.List;

public class NifSelector {

    private static String LINE_SEPARATOR = System.getProperty("line.separator");
    public final PcapNetworkInterface selectNetworkInterface(int key) throws IOException {
        List<PcapNetworkInterface> allDevs = null;
        try {
            allDevs = Pcaps.findAllDevs();
        } catch (PcapNativeException e) {
            throw new IOException(e.getMessage());
        }

        if (allDevs == null || allDevs.isEmpty()) {
            throw new IOException("No NIF to capture.");
        }

        showNifList(allDevs);

        return doSelect(allDevs,key);
    }

    protected void write(String msg) throws IOException {
        System.out.print(msg);
    }

    protected String read() throws IOException {
        BufferedReader reader
                = new BufferedReader(new InputStreamReader(System.in));
        return reader.readLine();
    }

     protected void showNifList(List<PcapNetworkInterface> nifs) throws IOException {
        StringBuilder sb = new StringBuilder(200);
        int nifIdx = 0;
        for (PcapNetworkInterface nif: nifs) {
            sb.append("NIF[").append(nifIdx).append("]: ")
                    .append(nif.getName()).append(LINE_SEPARATOR);

            if (nif.getDescription() != null) {
                sb.append("      : description: ")
                        .append(nif.getDescription()).append(LINE_SEPARATOR);
            }

            for (LinkLayerAddress addr: nif.getLinkLayerAddresses()) {
                sb.append("      : link layer address: ")
                        .append(addr).append(LINE_SEPARATOR);
            }

            for (PcapAddress addr: nif.getAddresses()) {
                sb.append("      : address: ")
                        .append(addr.getAddress()).append(LINE_SEPARATOR);
            }
            nifIdx++;
        }
        sb.append(LINE_SEPARATOR);


    }

    protected
    PcapNetworkInterface doSelect(List<PcapNetworkInterface> nifs,int key) throws IOException {
        int nifIdx;
        while (true) {

            int input=key-1;


            try {
                nifIdx = input;
                if (nifIdx < 0 || nifIdx >= nifs.size()) {
                    write("Invalid input." + LINE_SEPARATOR);
                    continue;
                }
                else {
                    break;
                }
            } catch (NumberFormatException e) {
                write("Invalid input." + LINE_SEPARATOR);
                continue;
            }
        }

        return nifs.get(nifIdx);
    }

}

