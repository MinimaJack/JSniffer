/*******************************************************************************
 * Copyright (c) 2013 MinimaJack
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser Public License v2.1
 * which accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 * 
 * Contributors:
 *     MinimaJack - initial API and implementation
 ******************************************************************************/
package org.jmangos.sniffer.network.model.impl;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;

import org.jmangos.sniffer.enums.Direction;
import org.jmangos.sniffer.enums.State;
import org.jmangos.sniffer.handler.PacketLogHandler;
import org.jmangos.sniffer.jna.WoWKeyReader;
import org.jmangos.sniffer.network.buffer.PacketBuffer;
import org.jmangos.sniffer.network.buffer.TCPPacketBuffer;
import org.jmangos.sniffer.network.buffer.impl.WoWPacketBuffer;
import org.jmangos.sniffer.network.model.NetworkChannel;
import org.jnetpcap.packet.PcapPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

/**
 * The Class WOWNetworkChannel.
 */
@Component
@Scope(value = "prototype")
@Lazy(value = true)
public class WOWNetworkChannel implements NetworkChannel {

    private final Logger log = LoggerFactory.getLogger(WOWNetworkChannel.class);
    private String channelId;
    /** The state. */
    private final EnumSet<State> state = EnumSet.noneOf(State.class);

    private final PacketBuffer csPacketBuffer = new WoWPacketBuffer();
    private final PacketBuffer scPacketBuffer = new WoWPacketBuffer();

    private final TCPPacketBuffer scTCPPacketBuffer = new TCPPacketBuffer();
    private final TCPPacketBuffer csTCPPacketBuffer = new TCPPacketBuffer();
    private final List<PacketLogHandler> packetLoggers = new ArrayList<PacketLogHandler>();
    @Autowired
    @Qualifier("WoWKeyReader")
    WoWKeyReader woWKeyReader;

    /**
     * @return the packetLogger
     */
    @Override
    public final List<PacketLogHandler> getPacketLoggers() {
        return this.packetLoggers;
    }

    /**
     * @param packetLogger
     *        the packetLogger to set
     */
    public final void addPacketLogger(final PacketLogHandler packetLogger) {
        this.packetLoggers.add(packetLogger);
    }

    @Override
    public boolean isConnected() {

        return this.state.contains(State.CONNECTED);
    }

    @Override
    public void addChannelState(final State channelState) {
        if (channelState.equals(State.DISCONNECTED) && getChannelState().contains(State.CONNECTED)) {
            removeChannelState(State.CONNECTED);
        }
        this.state.add(channelState);
    }

    @Override
    public boolean haveChannelState(final State channelState) {
        return getChannelState().contains(channelState);
    }

    public void removeChannelState(final State channelState) {

        this.state.remove(channelState);

    }

    @Override
    public EnumSet<State> getChannelState() {

        return this.state;
    }

    @Override
    public String getChannelId() {
        return this.channelId;
    }

    /**
     * @param channelId
     *        the channelId to set
     */
    @Override
    public final void setChannelId(final String channelId) {
        this.channelId = channelId;
    }

    @Override
    public void onResiveServerData(final PcapPacket p, final long time) {
        this.scTCPPacketBuffer.addPacket(p);
        this.csTCPPacketBuffer.processAck(p);
        int size = 0;
        for (final PcapPacket packet : this.csTCPPacketBuffer.getSequencedPackets()) {
            this.csPacketBuffer.addData(packet);
            while ((size = this.csPacketBuffer.nextAvaliablePacket()) > 0) {
                final byte[] packetData = this.csPacketBuffer.getNextPacket(size);
                this.onResiveClientData(time, packetData);
            }
        }
        this.csTCPPacketBuffer.flush();
    }

    @Override
    public void onResiveClientData(final PcapPacket p, final long time) {
        this.csTCPPacketBuffer.addPacket(p);
        this.scTCPPacketBuffer.processAck(p);
        int size = 0;
        for (final PcapPacket packet : this.scTCPPacketBuffer.getSequencedPackets()) {
            this.scPacketBuffer.addData(packet);
            while ((size = this.scPacketBuffer.nextAvaliablePacket()) > 0) {
                final byte[] packetData = this.scPacketBuffer.getNextPacket(size);
                this.onResiveServerData(time, packetData);
            }
        }
        this.scTCPPacketBuffer.flush();
    }

    @Override
    synchronized public void onResiveServerData(final long frameNumber, final byte[] buffer) {
        final ByteBuffer bytebuf = ByteBuffer.wrap(buffer);
        bytebuf.order(ByteOrder.LITTLE_ENDIAN);
        long opcode = 0;
        long size = 0;
        byte[] data = null;
        if (getChannelState().contains(State.AUTHED)) {
            final long header = bytebuf.getInt() & 0xFFFFFFFF;
            size = header >> 13;
            opcode = header & 0x1FFF;
            data = new byte[(int) size];
            bytebuf.get(data);
        } else {
            size = bytebuf.getShort();
            opcode = bytebuf.getInt();
            bytebuf.mark();
            data = new byte[(int) size - 4];
            bytebuf.get(data);
            bytebuf.reset();
            // old 0xc0b
            if ((opcode == 0x221) & !getChannelState().contains(State.NOT_ACCEPT_SEED)) {
                this.log.debug("Get new Seed");
                final byte[] serverSeed = new byte[16];
                final byte[] clientSeed = new byte[16];
                for (int i = 0; i < 16; i++) {
                    serverSeed[i] = bytebuf.get();
                }
                for (int i = 0; i < 16; i++) {
                    clientSeed[i] = bytebuf.get();
                }
                bytebuf.get();
                this.csPacketBuffer.getCrypt().setEncryptionSeed(clientSeed);
                this.scPacketBuffer.getCrypt().setEncryptionSeed(serverSeed);
            }

        }
        this.log.debug(String.format("Frame: %d; Resive packet %s Opcode: 0x%x OpcodeSize: %d",
                frameNumber, "SMSG", opcode, size));
        for (final PacketLogHandler logger : this.packetLoggers) {
            logger.onDecodePacket(this, Direction.SERVER, (int) size, (int) opcode, data,
                    (int) frameNumber);
        }
    }

    @Override
    public void onResiveClientData(final long frameNumber, final byte[] buffer) {
        final ByteBuffer bytebuf = ByteBuffer.wrap(buffer);
        long opcode = 0;
        long size = 0;
        byte[] data;
        bytebuf.order(ByteOrder.LITTLE_ENDIAN);
        if (getChannelState().contains(State.AUTHED)) {
            final long header = bytebuf.getInt() & 0xFFFFFFFF;
            size = header >> 13;
            opcode = (header & 0x1FFF);
            data = new byte[(int) size];
            bytebuf.get(data);
        } else {
            size = bytebuf.getShort();
            opcode = bytebuf.getInt();
            data = new byte[(int) size - 4];
            bytebuf.get(data);
            // old (opcode == 0x1a72) | (opcode == 0x3f3)
            if ((opcode == 0x1aa1) | (opcode == 0x9f1)) {
                this.log.debug("Init cryptography system for channel {}", this.getChannelId());
                addChannelState(State.AUTHED);
                this.csPacketBuffer.getCrypt().init(this.woWKeyReader.getKey());
                this.scPacketBuffer.getCrypt().init(this.woWKeyReader.getKey());
            }
        }
        this.log.debug(String.format("Frame: %d; Resive packet %s Opcode: 0x%x\n", frameNumber,
                "CMSG", opcode));
        for (final PacketLogHandler logger : this.packetLoggers) {
            logger.onDecodePacket(this, Direction.CLIENT, (int) size, (int) opcode, data,
                    (int) frameNumber);
        }
    }

    @Override
    public void addLogHandler(final PacketLogHandler logHandler) {
        this.packetLoggers.add(logHandler);
    }

    @Override
    public void setClientSeed(final byte[] seed) {
        this.csPacketBuffer.getCrypt().setEncryptionSeed(seed);

    }

    @Override
    public void setServerSeed(final byte[] seed) {
        this.scPacketBuffer.getCrypt().setEncryptionSeed(seed);

    }

}
