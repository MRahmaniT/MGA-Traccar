package org.traccar.protocol;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.traccar.BaseProtocolDecoder;
import org.traccar.handler.network.MainEventHandler;
import org.traccar.session.DeviceSession;
import org.traccar.Protocol;
import org.traccar.model.Position;

import java.net.SocketAddress;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

public class MgaProtocolDecoder extends BaseProtocolDecoder {

    public MgaProtocolDecoder(Protocol protocol) {
        super(protocol);
    }

    private static final Logger LOGGER = LoggerFactory.getLogger(MainEventHandler.class);

    @Override
    protected Object decode(
            Channel channel, SocketAddress remoteAddress, Object msg) throws Exception {

        ByteBuf buf = (ByteBuf) msg;
        return decodeBinary(buf, channel, remoteAddress);
    }

    private List<Position> decodeBinary(ByteBuf buf, Channel channel, SocketAddress remoteAddress) {

        List<Position> positions = new LinkedList<>();

        if (buf.readableBytes() < 1) {
            return null;
        }
        //*******************************Frame*******************************

        LOGGER.info("Packet Received, starting decode:");
        LOGGER.info("Remaining bytes: {}", buf.readableBytes());
        // Start of Frame (1 Bytes)
        byte sof = buf.readByte();
        if (sof != (byte) 0xAA) {
            while (sof != (byte) 0xAA) {
                sof = buf.readByte();
                if (buf.readableBytes() < 1) { // check readableBytes
                    return null;
                }
            }
        }
        LOGGER.info("sof: {}", sof);

        // Length (2 Bytes)
        int length = Short.reverseBytes(buf.readShort()) & 0xFFFF;
        LOGGER.info("length: {}", length);
        LOGGER.info("Remaining bytes: {}", buf.readableBytes());
        if (buf.readableBytes() < length + 1) {
            return null;
        }
        LOGGER.info("length: {}", length);

        // Serial Number (4 Bytes)
        int serialNumber = Integer.reverseBytes(buf.readInt());
        LOGGER.info("serial number: {}", serialNumber);
        String id = String.valueOf(serialNumber);
        DeviceSession deviceSession = getDeviceSession(channel, remoteAddress, id);
        if (deviceSession == null) {
            return null;
        }

        // Encrypted Data (Length - 6 Bytes)
        int encryptedDataSize = length - 6;
        byte[] encryptedData = new byte[encryptedDataSize];
        buf.readBytes(encryptedData);
        LOGGER.info("encrypted data: {}", encryptedData);

        // CRC Checksum (2 Bytes)
        int receivedCRC = buf.readUnsignedShort();
        LOGGER.info("received crc: {}", receivedCRC);

        // End of Frame (EOF)
        byte eof = buf.readByte();
        LOGGER.info("eof: {}", eof);
        if (eof != (byte) 0x55) {
            return null;
        }
        LOGGER.info("eof: {}", eof);

        //*******************************Packet*******************************
        // Decrypted Data Packets
        int decryptedSize = length - 6;
        ByteBuf decryptedBuf = Unpooled.wrappedBuffer(encryptedData);
        LOGGER.info("decrypted Size: {}", decryptedSize);
        LOGGER.info("encrypted Data: {}", encryptedData);

        // Start of Packet (1 Byte)
        byte sop = decryptedBuf.readByte();
        LOGGER.info("sop: {}", sop);
        if (sop != (byte) 0xAB) {
            return null;
        }

        // Data Count (1 Byte)
        int dataCount = decryptedBuf.readByte();
        LOGGER.info("dataCount: {}", dataCount);

        // Data (Decrypted Size - 3 Byte)
        int dataSize = decryptedSize - 3;
        byte[] allData = new byte[dataSize];
        decryptedBuf.readBytes(allData);
        LOGGER.info("dataSize: {}", dataSize);
        LOGGER.info("allData: {}", allData);

        // End of Packet (1 Byte)
        byte eop = decryptedBuf.readByte();
        if (eop != (byte) 0x57) {
            return null;
        }
        LOGGER.info("eop: {}", eop);

        //*******************************Data*******************************
        ByteBuf dataBuf = Unpooled.wrappedBuffer(allData);
        // Read Data
        for (int i = 0; i < dataCount; i++) {

            Position position = new Position(getProtocolName());
            position.setDeviceId(deviceSession.getDeviceId());

            if (dataBuf.readableBytes() < 4) {
                break;
            }

            // Start of Data (1 Byte)
            byte sod = dataBuf.readByte();
            if (sod != (byte) 0xAF) {
                while (sod != (byte) 0xAF) {
                    sod = dataBuf.readByte();
                    if (dataBuf.readableBytes() < 4) {
                        break;
                    }
                }
                if (dataBuf.readableBytes() < 4) {
                    break;
                }
            }
            LOGGER.info("sod: {}", sod);

            // Length (1 Byte)
            int dataLength = dataBuf.readUnsignedByte();
            LOGGER.info("data Length: {}", dataLength);

            // Type (1 Byte)
            int dataType = dataBuf.readUnsignedByte();
            LOGGER.info("data Type: {}", dataType);

            // Data (Length Byte)
            if (dataBuf.readableBytes() < dataLength + 1) {
                break;
            }

            byte[] data = new byte[dataLength];
            dataBuf.readBytes(data);
            //LOGGER.info("data: {}", data);
            LOGGER.info("data: {}", ByteBufUtil.hexDump(Unpooled.wrappedBuffer(data)).replaceAll("(.{2})", "$1 "));


            // End of Data (1 Byte)
            byte eod = dataBuf.readByte();
            if (eod != (byte) 0x5F) {
                break;
            }
            LOGGER.info("eod: {}", eod);

            ByteBuf wrappedData = Unpooled.wrappedBuffer(data);

            // Alarm Code (1 Byte)
            int alarmCode = wrappedData.readUnsignedByte();
            LOGGER.info("alarmCode: {}", alarmCode);
            switch (alarmCode){
                case 201 : position.addAlarm(Position.ALARM_COURSE_CHANGE);
                case 202 : position.addAlarm(Position.ALARM_OVER_SPEED_BEGIN);
                case 203 : position.addAlarm(Position.ALARM_OVER_SPEED_END);
                case 204 : position.addAlarm(Position.ALARM_LOCATION_TIMEOUT);
                case 205 : position.addAlarm(Position.ALARM_SIGNAL_LOST);
                case 206 : position.addAlarm(Position.ALARM_SIGNAL_BACK);
                case 207 : position.addAlarm(Position.ALARM_STOP);
                case 208 : position.addAlarm(Position.ALARM_MOVEMENT);
                case 209 : position.addAlarm(Position.ALARM_CURRENT_STATUS);
                case 210 : position.addAlarm(Position.ALARM_CHARGER_CONNECT);
                case 211 : position.addAlarm(Position.ALARM_CHARGER_DISCONNECT);
                case 212 : position.addAlarm(Position.ALARM_BUTTON_PRESSED);
                case 213 : position.addAlarm(Position.ALARM_CONFIGURATION_CHANGE);
                case 214 : position.addAlarm(Position.ALARM_LOCKER_UNSEALED);
                case 215 : position.addAlarm(Position.ALARM_LOCKER_SEALED);
                case 216 : position.addAlarm(Position.ALARM_TAMPER_OPENING);
                case 217 : position.addAlarm(Position.ALARM_TAMPER_CLOSING);
                case 218 : position.addAlarm(Position.ALARM_IMPACT);
                case 219 : position.addAlarm(Position.ALARM_UNAUTHORIZED);
                case 220 : position.addAlarm(Position.ALARM_TEMPERATURE);
                case 221 : position.addAlarm(Position.ALARM_HUMIDITY);
                case 222 : position.addAlarm(Position.ALARM_LOCK_MECHANISM_JAMMED);
                case 223 : position.addAlarm(Position.ALARM_SIM_CARD_PANEL_OPENED);
            }

            // Charger Status (1 Byte)
            int chargerStatus = wrappedData.readByte();
            LOGGER.info("chargerStatus: {}", chargerStatus);
            position.set(Position.KEY_CHARGE, chargerStatus);

            // Battery Voltage (2 Bytes)
            double batteryVoltage = (double) (Short.reverseBytes(wrappedData.readShort()) & 0xFFFF) / 1000;
            LOGGER.info("batteryVoltage: {}", batteryVoltage);
            position.set(Position.KEY_BATTERY, batteryVoltage);

            // Version (2 Bytes)
            double version = (double) (Short.reverseBytes(wrappedData.readShort()) & 0xFFFF) / 100;
            LOGGER.info("version: {}", version);
            position.set(Position.KEY_VERSION, version);

            // Wire Tamper (1 Byte)
            int wireTamper = wrappedData.readByte();
            LOGGER.info("wireTamper: {}", wireTamper);
            position.set(Position.KEY_WIRE_TAMPER, 1);

            // Lock Status (1 Byte)
            int lockStatus = wrappedData.readByte();
            LOGGER.info("lockStatus: {}", lockStatus);
            position.set(Position.KEY_LOCK, 1);

            // GSM Signal (1 Byte)
            int gsmSignal = wrappedData.readByte();
            LOGGER.info("gsmSignal: {}", gsmSignal);
            position.set(Position.KEY_GSM, gsmSignal);

            // Humidity
            int humidity = wrappedData.readByte();
            LOGGER.info("humidity: {}", humidity);
            position.set(Position.KEY_HUMIDITY, humidity);

            // Temperature
            int temperature = wrappedData.readByte();
            LOGGER.info("temperature: {}", temperature);
            position.set(Position.KEY_DEVICE_TEMP, temperature);

            // Flags
            boolean isFixed = false;
            boolean isStop = false;
            boolean lacCidValidity = false;

            int flags = wrappedData.readByte();
            LOGGER.info("flags: {}", flags);

            if ((flags & 1) == 1) {
                isFixed = true;
            }
            if (((flags >> 1) & 1) == 1) {
                isStop = true;
            }
            if (((flags >> 2) & 1) == 1) {
                lacCidValidity = true;
            }
            int tech = (flags >> 3) & 0b111;
            switch (tech) {
                case 0:
                    position.set(Position.KEY_TECHNOLOGY, "unknown");
                    break;
                case 1:
                    position.set(Position.KEY_TECHNOLOGY, "2G");
                    break;
                case 2:
                    position.set(Position.KEY_TECHNOLOGY, "3G");
                    break;
                case 3:
                    position.set(Position.KEY_TECHNOLOGY, "4G");
                    break;
                case 4:
                    position.set(Position.KEY_TECHNOLOGY, "5G");
                    break;
                default:
                    position.set(Position.KEY_TECHNOLOGY, "other");
                    break;
            }

            LOGGER.info("isStop: {}", isStop);
            LOGGER.info("motion: {}", !isStop);
            position.set(Position.KEY_MOTION, !isStop);
            switch (dataType){
                case (byte) 0x01 : {
                    // LAC (4 Bytes)
                    long lac = Integer.reverseBytes(wrappedData.readInt());
                    LOGGER.info("lac: {}", lac);
                    position.set(Position.KEY_LAC, lac);

                    // CID (4 Bytes)
                    long cid = Integer.reverseBytes(wrappedData.readInt());
                    LOGGER.info("cid: {}", cid);
                    position.set(Position.KEY_CID, cid);

                    // Unix Time (4 Bytes)
                    long unixTime = Integer.reverseBytes(wrappedData.readInt());
                    Date date = new Date(unixTime * 1000L);
                    LOGGER.info("date: {}", date);
                    position.setDeviceTime(date);

                    // Unix Time (4 Bytes)
                    long sinceTime = Integer.reverseBytes(wrappedData.readInt());
                    Date since = new Date(sinceTime * 1000L);
                    LOGGER.info("since: {}", since);
                    position.setFixTime(since);

                    // Latitude (4 Bytes)
                    long lat = Integer.reverseBytes(wrappedData.readInt());
                    double latitude = (double) lat /1000000;
                    LOGGER.info("latitude: {}", latitude);
                    position.setLatitude(latitude);

                    // Longitude (4 Bytes)
                    long lon = Integer.reverseBytes(wrappedData.readInt());
                    double longitude = (double) lon / 1000000;
                    LOGGER.info("longitude: {}", longitude);
                    position.setLongitude(longitude);

                    // Bearing (2 Bytes)
                    int bearing = Short.reverseBytes(wrappedData.readShort());
                    LOGGER.info("bearing: {}", bearing);
                    position.setCourse(bearing);

                    // Speed (1 Byte)
                    int speed = wrappedData.readByte();
                    LOGGER.info("speed: {}", speed);
                    position.setSpeed(speed*0.54);

                    // Sat (1 Byte)
                    int sat = wrappedData.readByte();
                    LOGGER.info("sat: {}", sat);
                    position.set(Position.KEY_SATELLITES, sat);

                    // Position Dilution Of Precision (2 Bytes)
                    double pdop = (double) (Short.reverseBytes(wrappedData.readShort())) / 100;
                    LOGGER.info("pdop: {}", pdop);
                    if (pdop < 3) {
                        position.setValid(true);
                    }
                }

                case (byte) 0x02 : {
                    // LAC (4 Bytes)
                    long lac = Integer.reverseBytes(wrappedData.readInt());
                    LOGGER.info("lac: {}", lac);
                    position.set(Position.KEY_LAC, lac);

                    // CID (4 Bytes)
                    long cid = Integer.reverseBytes(wrappedData.readInt());
                    LOGGER.info("cid: {}", cid);
                    position.set(Position.KEY_CID, cid);

                    // Unix Time (4 Bytes)
                    long unixTime = Integer.reverseBytes(wrappedData.readInt());
                    Date date = new Date(unixTime * 1000L);
                    LOGGER.info("date: {}", date);
                    position.setDeviceTime(date);

                    // Flags (4 Bytes)
                    long flag = Integer.reverseBytes(wrappedData.readInt());
                    LOGGER.info("flag: {}", flag);

                }

                case (byte) 0x03 : {
                    // LAC (4 Bytes)
                    long lac = Integer.reverseBytes(wrappedData.readInt());
                    LOGGER.info("lac: {}", lac);
                    position.set(Position.KEY_LAC, lac);

                    // CID (4 Bytes)
                    long cid = Integer.reverseBytes(wrappedData.readInt());
                    LOGGER.info("cid: {}", cid);
                    position.set(Position.KEY_CID, cid);

                    // Unix Time (4 Bytes)
                    long unixTime = Integer.reverseBytes(wrappedData.readInt());
                    Date date = new Date(unixTime * 1000L);
                    LOGGER.info("date: {}", date);
                    position.setDeviceTime(date);

                    // Unix Time (4 Bytes)
                    long sinceTime = Integer.reverseBytes(wrappedData.readInt());
                    Date since = new Date(sinceTime * 1000L);
                    LOGGER.info("since: {}", since);
                    position.setFixTime(since);

                    // Latitude (4 Bytes)
                    long lat = Integer.reverseBytes(wrappedData.readInt());
                    double latitude = (double) lat /1000000;
                    LOGGER.info("latitude: {}", latitude);
                    position.setLatitude(latitude);

                    // Longitude (4 Bytes)
                    long lon = Integer.reverseBytes(wrappedData.readInt());
                    double longitude = (double) lon / 1000000;
                    LOGGER.info("longitude: {}", longitude);
                    position.setLongitude(longitude);

                    // Bearing (2 Bytes)
                    int bearing = Short.reverseBytes(wrappedData.readShort());
                    LOGGER.info("bearing: {}", bearing);
                    position.setCourse(bearing);

                    // Speed (1 Byte)
                    int speed = wrappedData.readByte();
                    LOGGER.info("speed: {}", speed);
                    position.setSpeed(speed*0.54);

                    // Sat (1 Byte)
                    int sat = wrappedData.readByte();
                    LOGGER.info("sat: {}", sat);
                    position.set(Position.KEY_SATELLITES, sat);

                    // Position Dilution Of Precision (2 Bytes)
                    double pdop = (double) (Short.reverseBytes(wrappedData.readShort())) / 100;
                    LOGGER.info("pdop: {}", pdop);
                    if (pdop < 3) {
                        position.setValid(true);
                    }

                    // Illegal RFID Number
                    long rfid = Integer.reverseBytes(wrappedData.readInt());
                    LOGGER.info("rfid: {}", rfid);
                    position.set(Position.KEY_RFID, rfid);
                }
            }

            // Position
            positions.add(position);
        }

        return positions;
    }

}
