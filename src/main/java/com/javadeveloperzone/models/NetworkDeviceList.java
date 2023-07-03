package com.javadeveloperzone.models;


import java.util.List;


public class NetworkDeviceList {
    public NetworkDeviceList(String description, String name,List <String> linkLayerAddressList, int key,String IPAddress) {
        this.description = description;
        this.name = name;
        this.linkLayerAddressList=linkLayerAddressList;
        this.key=key;
        this.IPAddress=IPAddress;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getKey() {
        return key;
    }

    public void setKey(int key) {
        this.key = key;
    }

    public List<String> getLinkLayerAddressList() {
        return linkLayerAddressList;
    }

    public void setLinkLayerAddressList(List<String> linkLayerAddressList) {
        this.linkLayerAddressList = linkLayerAddressList;
    }

    public String getIPAddress() {
        return IPAddress;
    }

    public void setIPAddress(String IPAddress) {
        this.IPAddress = IPAddress;
    }

    String description;
   List< String> linkLayerAddressList;
    String name;
    int key;
    String IPAddress;
}


