package com.javadeveloperzone.models;

public class TotalPacket {
    private String dateFrom;
    private int numberOfPackets;
    private String dateTo;

    public String getDateFrom() {
        return dateFrom;
    }

    public void setDateFrom(String dateFrom) {
        this.dateFrom = dateFrom;
    }

    public int getNumberOfPackets() {
        return numberOfPackets;
    }

    public void setNumberOfPackets(int numberOfPackets) {
        this.numberOfPackets = numberOfPackets;
    }

    public String getDateTo() {
        return dateTo;
    }

    public void setDateTo(String dateTo) {
        this.dateTo = dateTo;
    }
}
