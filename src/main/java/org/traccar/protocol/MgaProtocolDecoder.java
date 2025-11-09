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
            for (int i = 1; i <= buf.readableBytes(); i++) {
                sof = buf.readByte();
                if (buf.readableBytes() < 1 || sof == (byte) 0xAA) {
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
        //TODO: check CRC

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
                for (int j = 1; j <= buf.readableBytes(); j++) {
                    sod = dataBuf.readByte();
                    if (dataBuf.readableBytes() < 4 || sod == (byte) 0xAF) {
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
            LOGGER.info("data: {}", ByteBufUtil.hexDump(Unpooled.wrappedBuffer(data)).replaceAll("(.{2})", "$1 "));


            // End of Data (1 Byte)
            byte eod = dataBuf.readByte();
            if (eod != (byte) 0x5F) {
                break;
            }
            LOGGER.info("eod: {}", eod);

            if (dataType == (byte) 0x01) {
                ByteBuf wrappedData = Unpooled.wrappedBuffer(data);

                // Alarm Code (1 Byte)
                int alarmCode = wrappedData.readUnsignedByte();
                LOGGER.info("alarmCode: {}", alarmCode);
                findAlarm(alarmCode, position);

                // Charger Status (1 Byte)
                int chargerStatus = wrappedData.readByte();
                LOGGER.info("chargerStatus: {}", chargerStatus);
                position.set(Position.KEY_CHARGE, chargerStatus);

                // Battery Voltage (2 Bytes)
                int batteryVoltage = Short.reverseBytes(wrappedData.readShort()) & 0xFFFF;
                LOGGER.info("batteryVoltage: {}", batteryVoltage);
                position.set(Position.KEY_BATTERY, batteryVoltage);

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

                // Version (2 Bytes)
                int version = Short.reverseBytes(wrappedData.readShort()) & 0xFFFF;
                LOGGER.info("version: {}", version);
                position.set(Position.KEY_VERSION, version);

                // Humidity
                int humidity = wrappedData.readByte();
                LOGGER.info("humidity: {}", humidity);
                position.set(Position.KEY_HUMIDITY, humidity);

                // Temperature
                int temperature = wrappedData.readByte();
                LOGGER.info("temperature: {}", temperature);
                position.set(Position.KEY_DEVICE_TEMP, temperature);

                // Unix Time (4 Bytes)
                long unixTime = Integer.reverseBytes(wrappedData.readInt());
                Date date = new Date(unixTime * 1000L);
                LOGGER.info("date: {}", date);
                position.setTime(date);

                // Latitude (4 Bytes)
                long lat = Integer.reverseBytes(wrappedData.readInt());
                double latitude = (double) lat / 1000000;
                LOGGER.info("latitude: {}", latitude);
                position.setLatitude(latitude);

                // Longitude (4 Bytes)
                long lon = Integer.reverseBytes(wrappedData.readInt());
                double longitude = (double) lon / 1000000;
                LOGGER.info("longitude: {}", longitude);
                position.setLongitude(longitude);

                // Bearing (2 Bytes)
                int bearing = Short.reverseBytes(wrappedData.readShort()) & 0xFFFF;
                LOGGER.info("bearing: {}", bearing);
                position.setCourse(bearing);

                // Speed (1 Byte)
                int speed = wrappedData.readByte();
                LOGGER.info("speed: {}", speed);
                position.setSpeed(speed * 0.54);

                // Sat (1 Byte)
                int sat = wrappedData.readByte();
                LOGGER.info("sat: {}", sat);
                position.set(Position.KEY_SATELLITES, sat);

                // Position Dilution Of Precision (2 Bytes)
                double pdop = (double) (Short.reverseBytes(wrappedData.readShort()) & 0xFFFF) / 100;
                LOGGER.info("pdop: {}", pdop);
                if (pdop < 3) {
                    position.setValid(true);
                }

                // Stop (1 Byte)
                int stop = wrappedData.readByte();
                LOGGER.info("stop: {}", stop);
                position.set(Position.KEY_MOTION, stop == 0);

            } else {
                ByteBuf wrappedData = Unpooled.wrappedBuffer(data);

                // Alarm Code (1 Byte)
                int alarmCode = wrappedData.readUnsignedByte();
                LOGGER.info("alarmCode: {}", alarmCode);
                findAlarm(alarmCode, position);

                // Flags P1
                int flags1 = wrappedData.readByte();
                LOGGER.info("flags P1: {}", flags1);

                // Tech(unregistered, unknown, 2g, 3g, 4g, 5g, other)
                int tech = flags1 & 0b00000111;
                switch (tech) {
                    case 0:
                        position.set(Position.KEY_TECHNOLOGY, "unregistered");
                        break;
                    case 1:
                        position.set(Position.KEY_TECHNOLOGY, "unknown");
                        break;
                    case 2:
                        position.set(Position.KEY_TECHNOLOGY, "2G");
                        break;
                    case 3:
                        position.set(Position.KEY_TECHNOLOGY, "3G");
                        break;
                    case 4:
                        position.set(Position.KEY_TECHNOLOGY, "4G");
                        break;
                    case 5:
                        position.set(Position.KEY_TECHNOLOGY, "5G");
                        break;
                    default:
                        position.set(Position.KEY_TECHNOLOGY, "other");
                        break;
                }
                LOGGER.info("Tceh: {}", Position.KEY_TECHNOLOGY);

                // Res
                boolean res;
                res = (flags1 & 0b00001000) != 0;
                LOGGER.info("Res: {}", res);

                // Charger Status
                boolean isCharging;
                isCharging = (flags1 & 0b00010000) != 0;
                LOGGER.info("isCharging: {}", isCharging);
                position.set(Position.KEY_CHARGE, isCharging);

                // Fix
                boolean isFixed;
                isFixed = (flags1 & 0b00100000) != 0;
                LOGGER.info("isFixed: {}", isFixed);

                // Stop
                boolean isStop;
                isStop = (flags1 & 0b01000000) != 0;
                position.set(Position.KEY_MOTION, !isStop);
                LOGGER.info("isStop: {}", isStop);

                // LAC CID Validity
                boolean lacCidValidity;
                lacCidValidity = (flags1 & 0b10000000) != 0;
                LOGGER.info("lacCidValidity: {}", lacCidValidity);

                // Flags P2
                int flags2 = wrappedData.readByte();
                LOGGER.info("flags: {}", flags1);

                // Is Unlock Allowed
                boolean isUnlockAllowed;
                isUnlockAllowed = (flags1 & 0b00000001) != 0;
                position.set(Position.KEY_LOCK, isUnlockAllowed);
                LOGGER.info("isUnlockAllowed: {}", isUnlockAllowed);

                // IS Rope Closed
                boolean isRopeClosed;
                isRopeClosed = (flags1 & 0b00000010) != 0;
                position.set(Position.KEY_WIRE_TAMPER, isRopeClosed);
                LOGGER.info("isRopeClose: {}", isRopeClosed);

                // IS Mechanic Closed
                boolean isMechanicClosed;
                isMechanicClosed = (flags1 & 0b00000100) != 0;
                //position.set(Position.KEY_WIRE_TAMPER, isMechanicClosed);
                LOGGER.info("isMechanicClosed: {}", isMechanicClosed);

                // Is Coil Open
                boolean isCoilOpen;
                isCoilOpen = (flags1 & 0b00001000) != 0;
                //position.set(Position.KEY_WIRE_TAMPER, isMechanicClosed);
                LOGGER.info("isCoilOpen: {}", isCoilOpen);

                // GSM Signal (1 Byte)
                int gsmSignal = wrappedData.readByte();
                position.set(Position.KEY_GSM, gsmSignal);
                LOGGER.info("gsmSignal: {}", gsmSignal);

                // Version (2 Bytes) --> CRC
                double version = (double) (Short.reverseBytes(wrappedData.readShort()) & 0xFFFF) / 100;
                position.set(Position.KEY_VERSION, version);
                LOGGER.info("version: {}", version);

                // Battery Voltage (2 Bytes)
                double batteryVoltage = (double) (Short.reverseBytes(wrappedData.readShort()) & 0xFFFF) / 1000;
                LOGGER.info("batteryVoltage: {}", batteryVoltage);
                position.set(Position.KEY_BATTERY, batteryVoltage);

                // Humidity
                int humidity = wrappedData.readByte();
                LOGGER.info("humidity: {}", humidity);
                position.set(Position.KEY_HUMIDITY, humidity);

                // Temperature
                int temperature = wrappedData.readByte();
                LOGGER.info("temperature: {}", temperature);
                position.set(Position.KEY_DEVICE_TEMP, temperature);

                switch (dataType) {
                    case (byte) 0x11: {
                        // LAC (2 Bytes)
                        long lac = Short.reverseBytes(wrappedData.readShort());
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
                        double latitude = (double) lat / 1000000;
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

                        // Position Dilution Of Precision (2 Bytes)
                        double pdop = (double) (Short.reverseBytes(wrappedData.readShort())) / 100;
                        LOGGER.info("pdop: {}", pdop);
                        if (pdop < 3) {
                            position.setValid(true);
                        }

                        // Sat (1 Byte)
                        int sat = wrappedData.readByte();
                        LOGGER.info("sat: {}", sat);
                        position.set(Position.KEY_SATELLITES, sat);

                        // Speed (1 Byte)
                        int speed = wrappedData.readByte();
                        LOGGER.info("speed: {}", speed);
                        position.setSpeed(speed * 0.54);
                    }

                    case (byte) 0x02: {
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

                    case (byte) 0x03: {
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
                        double latitude = (double) lat / 1000000;
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
                        position.setSpeed(speed * 0.54);

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
            }

            // Position
            positions.add(position);
        }

        return positions;
    }
    private void findAlarm (int alarmCode, Position position) {
        switch (alarmCode) {
            case 201:
                position.addAlarm(Position.ALARM_COURSE_CHANGE);
                break;
            case 202:
                position.addAlarm(Position.ALARM_OVER_SPEED_BEGIN);
                break;
            case 203:
                position.addAlarm(Position.ALARM_OVER_SPEED_END);
                break;
            case 204:
                position.addAlarm(Position.ALARM_LOCATION_TIMEOUT);
                break;
            case 205:
                position.addAlarm(Position.ALARM_SIGNAL_LOST);
                break;
            case 206:
                position.addAlarm(Position.ALARM_SIGNAL_BACK);
                break;
            case 207:
                position.addAlarm(Position.ALARM_STOP);
                break;
            case 208:
                position.addAlarm(Position.ALARM_MOVEMENT);
                break;
            case 209:
                position.addAlarm(Position.ALARM_CURRENT_STATUS);
                break;
            case 210:
                position.addAlarm(Position.ALARM_CHARGER_CONNECT);
                break;
            case 211:
                position.addAlarm(Position.ALARM_CHARGER_DISCONNECT);
                break;
            case 212:
                position.addAlarm(Position.ALARM_BUTTON_PRESSED);
                break;
            case 213:
                position.addAlarm(Position.ALARM_CONFIGURATION_CHANGE);
                break;
            case 214:
                position.addAlarm(Position.ALARM_LOCKER_UNSEALED);
                break;
            case 215:
                position.addAlarm(Position.ALARM_LOCKER_SEALED);
                break;
            case 216:
                position.addAlarm(Position.ALARM_TAMPER_OPENING);
                break;
            case 217:
                position.addAlarm(Position.ALARM_TAMPER_CLOSING);
                break;
            case 218:
                position.addAlarm(Position.ALARM_TEMPERATURE);
                break;
            case 219:
                position.addAlarm(Position.ALARM_TEMPERATURE);
                break;
            case 220:
                position.addAlarm(Position.ALARM_IMPACT);
                break;
            case 221:
                position.addAlarm(Position.ALARM_HUMIDITY);
                break;
            case 222:
                position.addAlarm(Position.ALARM_LOW_BATTERY);
                break;
            case 223:
                position.addAlarm(Position.ALARM_WRONG_PASSWORD);
                break;
            case 224:
                position.addAlarm(Position.ALARM_LONG_TIME_UNLOCKED);
                break;
            case 225:
                position.addAlarm(Position.ALARM_ILLEGAL_RFID);
                break;
            case 226:
                position.addAlarm(Position.ALARM_GEOFENCE_ENTER);
                break;
            case 227:
                position.addAlarm(Position.ALARM_GEOFENCE_EXIT);
                break;
            case 228:
                position.addAlarm(Position.ALARM_BACK_COVER_OPEN);
                break;
            case 229:
                position.addAlarm(Position.ALARM_TAMPER_OPENING);
                break;
            case 230:
                position.addAlarm(Position.ALARM_TAMPER_CLOSING);
                break;
            default:
                position.addAlarm(Position.ALARM_UNKNOWN);
                break;
        }
    }

}
