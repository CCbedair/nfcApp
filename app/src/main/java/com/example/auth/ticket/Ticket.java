package com.example.auth.ticket;

import android.util.Log;

import com.example.auth.app.ulctools.Commands;
import com.example.auth.app.ulctools.Utilities;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;

/**
 * TODO: Complete the implementation of this class. Most of the code are already implemented. You
 * will need to change the keys, design and implement functions to issue and validate tickets.
 */
public class Ticket {

    private static byte[] defaultAuthenticationKey = "BREAKMEIFYOUCAN!".getBytes();// 16-byte key
    private static String infoToShow; // Use this to show messages in Normal Mode

    /**
     * TODO: Change these according to your design. Diversify the keys.
     */
    private static byte[] writeAuthenticationKey = defaultAuthenticationKey;
    private static byte[] authenticationKey =  "!NACUOYFIEMKAERB".getBytes(); //defaultAuthenticationKey;
    private static byte[] hmacKey = "0123456789ABCDEF".getBytes(); // min 16-byte key

    public static byte[] data = new byte[192];

    private static TicketMac macAlgorithm; // For computing HMAC over ticket data, as needed
    private static Utilities utils;
    private static Commands ul;

    private Boolean isValid = false;
    private short validTickets = 0;
    private short expiry = 0;
    private short counter;
    byte[] uuid;
    byte[] cardMac;

    HashMap<String, Integer> hmap = new HashMap<String, Integer>();

    private short invertCounterBytes(byte[] c) {
        byte[] currentCounterValue = new byte[2];
        currentCounterValue[0] = c[1];
        currentCounterValue[1] = c[0];
        return ByteBuffer.wrap(currentCounterValue).getShort();
    }

    private void readTicketData() {

        /*Adding elements to HashMap*/
        hmap.put("validTicket0", 20 * 4);
        hmap.put("expiry0", 20 * 4 + 2);
        hmap.put("cardMac0", 21 * 4);

        hmap.put("validTicket1", 30 * 4);
        hmap.put("expiry1", 30 * 4 + 2);
        hmap.put("cardMac1", 31 * 4);

        uuid = Arrays.copyOfRange(Ticket.data, 0, 8);
        counter = invertCounterBytes(Arrays.copyOfRange(Ticket.data, 41 * 4, 41 * 4 + 2));
        if (counter % 2 == 0) {
            Utilities.log("Even Counter with value: " + counter, false);
            validTickets = ByteBuffer.wrap(Arrays.copyOfRange(Ticket.data, hmap.get("validTicket0"), hmap.get("validTicket0") + 2)).getShort();
            expiry = ByteBuffer.wrap(Arrays.copyOfRange(Ticket.data, hmap.get("expiry0"), hmap.get("expiry0") + 2)).getShort();
            cardMac = ByteBuffer.wrap(Arrays.copyOfRange(Ticket.data, hmap.get("cardMac0"), hmap.get("cardMac0") + 4)).array();
        } else {
            Utilities.log("Odd Counter with value: " + counter, false);
            validTickets = ByteBuffer.wrap(Arrays.copyOfRange(Ticket.data, hmap.get("validTicket1"), hmap.get("validTicket1") + 2)).getShort();
            expiry = ByteBuffer.wrap(Arrays.copyOfRange(Ticket.data, hmap.get("expiry1"), hmap.get("expiry1") + 2)).getShort();
            cardMac = ByteBuffer.wrap(Arrays.copyOfRange(Ticket.data, hmap.get("cardMac1"), hmap.get("cardMac1") + 4)).array();
        }
    }

    private void writeTicketData() {
        Utilities.log("In writing function" + validTickets, false);

        ByteBuffer writeData = ByteBuffer.allocate(8);
        writeData.putShort(validTickets).putShort(expiry);
        Utilities.log("Success write data" + validTickets, false);

        counter++;
        Utilities.log("Generating mac", false);
        ByteBuffer macPayload = ByteBuffer.allocate(8);
        macPayload.putShort(validTickets).putShort(expiry).putInt(counter);
        byte[] mac = macAlgorithm.generateMac(macPayload.array());
        writeData.put(Arrays.copyOfRange(mac, 0, 4));
        Utilities.log("Done generating mac " + mac.length, false);
        boolean res;
        Utilities.log("Starting 2 page write" + validTickets, false);
        if (counter % 2 == 0) {
            Utilities.log("Even Counter with value: " + counter, false);
            res = utils.writePages(writeData.array(), 0, hmap.get("validTicket0")/4, 2);

        } else {
            Utilities.log("Odd Counter with value: " + counter, false);
            res = utils.writePages(writeData.array(), 0, hmap.get("validTicket1")/4, 2);
        }
        Utilities.log("Done 2 page write" + validTickets, false);
        byte[] inc = new byte[4];
        inc[0] = 0x01;
        Utilities.log("Inc counter" + validTickets, false);
        utils.writePages(inc, 0, 41, 1);
        Utilities.log("Done inc counter" + validTickets, false);

    }


    /**
     * Create a new ticket
     */
    public Ticket() throws GeneralSecurityException {
        // Set HMAC key for the ticket
        macAlgorithm = new TicketMac();
        ul = new Commands();
        utils = new Utilities(ul);
    }

    /**
     * After validation, get ticket status: was it valid or not?
     */
    public boolean isValid() {
        return isValid;
    }

    /**
     * After validation, get the number of remaining uses
     */
    public int getRemainingUses() {
        return validTickets;
    }

    /**
     * After validation, get the expiry time
     */
    public int getExpiryTime() {
        return expiry;
    }

    /**
     * After validation/issuing, get information
     */
    public static String getInfoToShow() {
        String tmp = infoToShow;
        infoToShow = "";
        return tmp;
    }

    /**
     * Issue new tickets
     * <p>
     * TODO: IMPLEMENT
     */
    public boolean issue(int daysValid, int uses) throws GeneralSecurityException {
        boolean res;
        Ticket.data = utils.readMemory();
        readTicketData();
        setNewHmacKey(uuid);
        Utilities.log("Counter Value" + counter, false);
        Utilities.log("UUID Value" + uuid, false);
        Utilities.log("ValidRides Value" + validTickets, false);
        Utilities.log("Expiry Value" + expiry, false);

        // Authenticate
        res = utils.authenticate(authenticationKey);
        if (!res) {
            Utilities.log("Authentication failed in issue()", true);
            infoToShow = "Authentication failed";
            return false;
        }
        ByteBuffer macPayload = ByteBuffer.allocate(8);
        macPayload.putShort(validTickets).putShort(expiry).putInt(counter);
        byte[] currentMac = Arrays.copyOfRange(macAlgorithm.generateMac(macPayload.array()),0,4);

        if (Arrays.equals(currentMac, cardMac)) {
            if (expiry >= System.currentTimeMillis() / (1000 * 60 * 60 * 24) || expiry == 0) {
                validTickets += 5;
                infoToShow = "Topped off. Valid Rides: "+validTickets;
            } else {
                validTickets = 5;
                expiry = 0;
                infoToShow = "New Card Issued. Valid Rides: "+validTickets;
            }
        } else {
//            Utilities.log("Mac Values are not the same", false);
//            infoToShow = "Invalid Card!";
//            isValid = false;
//            return false;
            validTickets = 5;
            expiry = 0;
            infoToShow = "New Card Issued. Valid Rides: "+validTickets;
        }

        writeTicketData();

        return true;
    }

    public void prepCard() {
        Boolean res = utils.authenticate(defaultAuthenticationKey);
        if (!res) {
            Utilities.log("Authentication failed in issue()", true);
            infoToShow = "Authentication failed";
        } else {
            byte[] appVersion = new byte[4];
            appVersion[0] = 0x01;
            utils.writePages(appVersion, 0, 19, 1);
            Utilities.log("Wrote app version", false);

            //write to memory protection page 2Ah
            byte[] inc = new byte[4];
            inc[0] = 0x03;
            inc[1] = 0x00;
            inc[2] = 0x00;
            inc[3] = 0x00;
            utils.writePages(inc, 0, 42, 1);
            Utilities.log("Wrote memory protect start page 03h", false);

            inc[0] = 0x01;
            inc[1] = 0x00;
            inc[2] = 0x00;
            inc[3] = 0x00;
            utils.writePages(inc, 0, 43, 1);
            Utilities.log("write access restricted, read access allowed", false);

//        write auth key 4 times
            byte[] auth = new byte[4];
            auth[0] = writeAuthenticationKey[writeAuthenticationKey.length -1];
            auth[1] = writeAuthenticationKey[writeAuthenticationKey.length -2];
            auth[2] = writeAuthenticationKey[writeAuthenticationKey.length -3];
            auth[3] = writeAuthenticationKey[writeAuthenticationKey.length -4];
            utils.writePages(auth,0, 44, 1);
            Utilities.log("Wrote memory First Byte", false);

            auth[0] = writeAuthenticationKey[writeAuthenticationKey.length -5];
            auth[1] = writeAuthenticationKey[writeAuthenticationKey.length -6];
            auth[2] = writeAuthenticationKey[writeAuthenticationKey.length -7];
            auth[3] = writeAuthenticationKey[writeAuthenticationKey.length -8];
            utils.writePages(auth, 0, 45, 1);
            Utilities.log("Wrote memory Second Byte", false);

            auth[0] = writeAuthenticationKey[writeAuthenticationKey.length -9];
            auth[1] = writeAuthenticationKey[writeAuthenticationKey.length -10];
            auth[2] = writeAuthenticationKey[writeAuthenticationKey.length -11];
            auth[3] = writeAuthenticationKey[writeAuthenticationKey.length -12];
            utils.writePages(auth, 0, 46, 1);
            Utilities.log("Wrote memory Third", false);

            auth[0] = writeAuthenticationKey[writeAuthenticationKey.length -13];
            auth[1] = writeAuthenticationKey[writeAuthenticationKey.length -14];
            auth[2] = writeAuthenticationKey[writeAuthenticationKey.length -15];
            auth[3] = writeAuthenticationKey[writeAuthenticationKey.length -16];
            utils.writePages(auth, 0, 47, 1);
            Utilities.log("Wrote memory Forth byte", false);

            infoToShow = "Card Successfully Prepared";
        }
    }
    /**
     * Use ticket once
     * <p>
     * TODO: IMPLEMENT
     */
    public boolean use() throws GeneralSecurityException {
        boolean res;

        Ticket.data = utils.readMemory();
        readTicketData();
        setNewHmacKey(uuid);

        Utilities.log("Counter Value" + counter, false);
        Utilities.log("UUID Value" + uuid, false);
        Utilities.log("ValidRides Value" + validTickets, false);
        Utilities.log("Expiry Value" + expiry, false);

        // Authenticate
        res = utils.authenticate(authenticationKey);
        if (!res) {
            Utilities.log("Authentication failed in Use()", true);
            infoToShow = "Authentication failed";
            return false;
        }

        ByteBuffer macPayload = ByteBuffer.allocate(8);
        macPayload.putShort(validTickets).putShort(expiry).putInt(counter);
        byte[] currentMac = Arrays.copyOfRange(macAlgorithm.generateMac(macPayload.array()),0,4);
        
        isValid = Arrays.equals(currentMac, cardMac) && validTickets >0 && (expiry >= System.currentTimeMillis() / (1000 * 60 * 60 * 24) || expiry == 0);
        if (isValid){
            long currentDay = System.currentTimeMillis() / (1000 * 60 * 60 * 24);
            if(expiry == 0){
                expiry = ((short) currentDay) ;
            }
            validTickets -= 1;
            writeTicketData();


            long exp = ((long) expiry + 1) *24 * 60;
            long cur = System.currentTimeMillis() / (1000 * 60);
            long hrs = (exp - cur)/ 60 - 2;
            long min = ((exp - cur) % 60);
            infoToShow = "Accepted. Rides Left: "+ validTickets+" Expiring Time:" + hrs + "h " + min + "m";
            return true;
        }
        else {
            if (!Arrays.equals(currentMac, cardMac))
                infoToShow = "Invalid Card";
            else if (validTickets <= 0)
                infoToShow = "Refused. ValidRides: " + validTickets;
            else{
                infoToShow = "Refused. Ticket Expired";
            }
            return false;
        }
    }

    private void setNewHmacKey(byte[] uuid) throws GeneralSecurityException {
        uuid = Arrays.copyOfRange(data, 0, 8);
        byte[] newHmacKey = new byte[hmacKey.length + uuid.length];

        System.arraycopy(hmacKey, 0, newHmacKey, 0, hmacKey.length);
        System.arraycopy(uuid, 0, newHmacKey, hmacKey.length, uuid.length);
        macAlgorithm.setKey(newHmacKey);
    }

}