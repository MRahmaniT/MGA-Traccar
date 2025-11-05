package org.traccar.protocol;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.traccar.BaseProtocolDecoder;
import org.traccar.handler.network.MainEventHandler;
import org.traccar.helper.*;
import org.traccar.model.CellTower;
import org.traccar.model.Network;
import org.traccar.session.DeviceSession;
import org.traccar.NetworkMessage;
import org.traccar.Protocol;
import org.traccar.model.Position;

import java.net.SocketAddress;
import java.util.LinkedList;
import java.util.List;

public class MgaProtocolDecoder extends BaseProtocolDecoder {

    public MgaProtocolDecoder(Protocol protocol) {
        super(protocol);
    }

    public static final int MSG_DATA = 0x10;
    public static final int MSG_HEARTBEAT = 0x1A;
    public static final int MSG_RESPONSE = 0x1C;

    private static final Logger LOGGER = LoggerFactory.getLogger(MainEventHandler.class);

    @Override
    protected Object decode(
            Channel channel, SocketAddress remoteAddress, Object msg) throws Exception {

        ByteBuf buf = (ByteBuf) msg;
        return decodeBinary(buf, channel, remoteAddress);
    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    private static double convertCoordinate(int raw) {
        int degrees = raw / 1000000;
        double minutes = (raw % 1000000) / 10000.0;
        return degrees + minutes / 60;
    }

    private void decodeStatus(Position position, ByteBuf buf) {

        int value = buf.readUnsignedByte();

        position.set(Position.KEY_IGNITION, BitUtil.check(value, 0));
        position.set(Position.KEY_DOOR, BitUtil.check(value, 6));

        value = buf.readUnsignedByte();

        position.set(Position.KEY_CHARGE, BitUtil.check(value, 0));
        position.set(Position.KEY_BLOCKED, BitUtil.check(value, 1));

        if (BitUtil.check(value, 2)) {
            position.addAlarm(Position.ALARM_SOS);
        }
        if (BitUtil.check(value, 3) || BitUtil.check(value, 4)) {
            position.addAlarm(Position.ALARM_GPS_ANTENNA_CUT);
        }
        if (BitUtil.check(value, 4)) {
            position.addAlarm(Position.ALARM_OVERSPEED);
        }

        value = buf.readUnsignedByte();

        if (BitUtil.check(value, 2)) {
            position.addAlarm(Position.ALARM_FATIGUE_DRIVING);
        }
        if (BitUtil.check(value, 3)) {
            position.addAlarm(Position.ALARM_TOW);
        }

        buf.readUnsignedByte(); // reserved

    }

    static boolean isLongFormat(ByteBuf buf) {
        return buf.getUnsignedByte(buf.readerIndex() + 8) == 0;
    }

    static void decodeBinaryLocation(ByteBuf buf, Position position) {

        DateBuilder dateBuilder = new DateBuilder()
                .setDay(BcdUtil.readInteger(buf, 2))
                .setMonth(BcdUtil.readInteger(buf, 2))
                .setYear(BcdUtil.readInteger(buf, 2))
                .setHour(BcdUtil.readInteger(buf, 2))
                .setMinute(BcdUtil.readInteger(buf, 2))
                .setSecond(BcdUtil.readInteger(buf, 2));
        position.setTime(dateBuilder.getDate());

        double latitude = convertCoordinate(BcdUtil.readInteger(buf, 8));
        double longitude = convertCoordinate(BcdUtil.readInteger(buf, 9));

        byte flags = buf.readByte();
        position.setValid(BitUtil.check(flags, 0));
        position.setLatitude(BitUtil.check(flags, 1) ? latitude : -latitude);
        position.setLongitude(BitUtil.check(flags, 2) ? longitude : -longitude);

        position.setSpeed(BcdUtil.readInteger(buf, 2));
        position.setCourse(buf.readUnsignedByte() * 2.0);
    }

    private List<Position> decodeBinary(ByteBuf buf, Channel channel, SocketAddress remoteAddress) {

        List<Position> positions = new LinkedList<>();

        // ///////////////////////////////////////////////////////
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

        // Length (2 Bytes)
        int length = Short.reverseBytes(buf.readShort()) & 0xFFFF;
        if (buf.readableBytes() < length + 1) {
            return null;
        }

        LOGGER.info("length: {}", length);

        // Serial Number (4 Bytes)
        int serialNumber = Integer.reverseBytes(buf.readInt());
        LOGGER.info("serial number: {}", serialNumber);

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
        //LOGGER.info("eof?: {}", eof);
        //LOGGER.info("remaining: {}", buf.readableBytes());
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


            switch (dataType){
                case (byte) 0x01 : {
                    ByteBuf wrappedData = Unpooled.wrappedBuffer(data);

                    // Alarm Code (1 Byte)
                    int alarmCode = wrappedData.readByte();
                    LOGGER.info("alarmCode: {}", alarmCode);

                    // Charger Status (1 Byte)
                    int chargerStatus = wrappedData.readByte();
                    LOGGER.info("chargerStatus: {}", chargerStatus);

                    // Battery Voltage (2 Bytes)
                    int batteryVoltage = Short.reverseBytes(wrappedData.readShort()) & 0xFFFF;
                    LOGGER.info("batteryVoltage: {}", batteryVoltage);

                    // Wire Tamper (1 Byte)
                    int wireTamper = wrappedData.readByte();
                    LOGGER.info("wireTamper: {}", wireTamper);

                    // Lock Status (1 Byte)
                    int lockStatus = wrappedData.readByte();
                    LOGGER.info("lockStatus: {}", lockStatus);

                    // GSM Signal (1 Byte)
                    int gsmSignal = wrappedData.readByte();
                    LOGGER.info("gsmSignal: {}", gsmSignal);

                    // Version (2 Bytes)
                    int version = Short.reverseBytes(wrappedData.readShort()) & 0xFFFF;
                    LOGGER.info("version: {}", version);

                    // GPS Data (21 Bytes)
                    int gpsDataSize = 21;
                    byte[] gpsData = new byte[gpsDataSize];
                    wrappedData.readBytes(gpsData);
                    LOGGER.info("gpsData: {}", gpsData);
                }
            }
        }


        // ///////////////////////////////////////////////////////

        boolean longFormat = isLongFormat(buf);

        buf.readByte(); // header

        String id = String.valueOf(Long.parseLong(ByteBufUtil.hexDump(buf.readSlice(5))));
        DeviceSession deviceSession = getDeviceSession(channel, remoteAddress, id);
        if (deviceSession == null) {
            return null;
        }

        int protocolVersion = 0;
        if (longFormat) {
            protocolVersion = buf.readUnsignedByte();
        }

        int version = BitUtil.from(buf.readUnsignedByte(), 4);
        buf.readUnsignedShort(); // length

        boolean responseRequired = false;

        while (buf.readableBytes() >= 17) {

            Position position = new Position(getProtocolName());
            position.setDeviceId(deviceSession.getDeviceId());

            decodeBinaryLocation(buf, position);

            if (longFormat) {

                position.set(Position.KEY_ODOMETER, buf.readUnsignedInt() * 1000);
                position.set(Position.KEY_SATELLITES, buf.readUnsignedByte());

                buf.readUnsignedInt(); // vehicle id combined

                int status = buf.readUnsignedShort();
                position.addAlarm(BitUtil.check(status, 1) ? Position.ALARM_GEOFENCE_ENTER : null);
                position.addAlarm(BitUtil.check(status, 2) ? Position.ALARM_GEOFENCE_EXIT : null);
                position.addAlarm(BitUtil.check(status, 3) ? Position.ALARM_POWER_CUT : null);
                position.addAlarm(BitUtil.check(status, 4) ? Position.ALARM_VIBRATION : null);
                if (BitUtil.check(status, 5)) {
                    responseRequired = true;
                }
                position.set(Position.KEY_BLOCKED, BitUtil.check(status, 7));
                position.addAlarm(BitUtil.check(status, 8 + 3) ? Position.ALARM_LOW_BATTERY : null);
                position.addAlarm(BitUtil.check(status, 8 + 6) ? Position.ALARM_FAULT : null);
                position.set(Position.KEY_STATUS, status);

                int battery = buf.readUnsignedByte();
                if (battery == 0xff) {
                    position.set(Position.KEY_CHARGE, true);
                } else {
                    position.set(Position.KEY_BATTERY_LEVEL, battery);
                }

                CellTower cellTower = CellTower.fromCidLac(
                        getConfig(), buf.readUnsignedShort(), buf.readUnsignedShort());
                cellTower.setSignalStrength((int) buf.readUnsignedByte());
                position.setNetwork(new Network(cellTower));

                if (protocolVersion == 0x17 || protocolVersion == 0x19) {
                    buf.readUnsignedByte(); // geofence id
                    buf.skipBytes(3); // reserved
                    buf.skipBytes(buf.readableBytes() - 1);
                }

            } else if (version == 1) {

                position.set(Position.KEY_SATELLITES, buf.readUnsignedByte());
                position.set(Position.KEY_POWER, buf.readUnsignedByte());

                buf.readByte(); // other flags and sensors

                position.setAltitude(buf.readUnsignedShort());

                int cid = buf.readUnsignedShort();
                int lac = buf.readUnsignedShort();
                int rssi = buf.readUnsignedByte();

                if (cid != 0 && lac != 0) {
                    CellTower cellTower = CellTower.fromCidLac(getConfig(), cid, lac);
                    cellTower.setSignalStrength(rssi);
                    position.setNetwork(new Network(cellTower));
                } else {
                    position.set(Position.KEY_RSSI, rssi);
                }

            } else if (version == 2) {

                int fuel = buf.readUnsignedByte() << 8;

                decodeStatus(position, buf);
                position.set(Position.KEY_ODOMETER, buf.readUnsignedInt() * 1000);

                fuel += buf.readUnsignedByte();
                position.set(Position.KEY_FUEL, fuel);

            } else if (version == 3) {

                BitBuffer bitBuffer = new BitBuffer(buf);

                position.set("fuel1", bitBuffer.readUnsigned(12));
                position.set("fuel2", bitBuffer.readUnsigned(12));
                position.set("fuel3", bitBuffer.readUnsigned(12));
                position.set(Position.KEY_ODOMETER, bitBuffer.readUnsigned(20) * 1000);

                int status = bitBuffer.readUnsigned(24);
                position.set(Position.KEY_IGNITION, BitUtil.check(status, 0));
                position.set(Position.KEY_STATUS, status);

            }

            positions.add(position);

        }

        int index = buf.readUnsignedByte();

        if (channel != null && responseRequired) {
            if (protocolVersion < 0x19) {
                channel.writeAndFlush(new NetworkMessage("(P35)", remoteAddress));
            } else {
                channel.writeAndFlush(new NetworkMessage("(P69,0," + index + ")", remoteAddress));
            }
        }

        return positions;
    }

}
