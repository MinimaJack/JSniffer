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
package org.jmangos.sniffer.network.buffer.impl;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.jmangos.sniffer.crypt.Crypt;
import org.jmangos.sniffer.network.buffer.PacketBuffer;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;

public class WoWPacketBuffer implements PacketBuffer {

    public static final int BUFFER_SIZE = 65536 * 4;
    private final ByteBuffer buffer;
    private final Crypt crypt = new Crypt();
    private boolean needDecrypt = true;

    public WoWPacketBuffer() {
        this.buffer = ByteBuffer.allocate(BUFFER_SIZE);
        this.buffer.order(ByteOrder.LITTLE_ENDIAN);
    }

    @Override
    public int nextAvaliablePacket() {
        if (this.buffer.position() < 4) {
            return 0;
        }
        if (this.crypt.isEnabled()) {
            if (this.needDecrypt) {
                final int headerF = this.buffer.getInt(0);
                long data = 0;
                final byte[] header = intToByteArray(headerF);
                final byte[] decryptedHeader = this.crypt.decrypt(header);
                data |= (decryptedHeader[3] & 0xFF);
                data <<= 8;
                data |= (decryptedHeader[2] & 0xFF);
                data <<= 8;
                data |= (decryptedHeader[1] & 0xFF);
                data <<= 8;
                data |= (decryptedHeader[0] & 0xFF);
                this.buffer.putInt(0, (int) data);
                this.needDecrypt = false;
            }
            final long data = this.buffer.getInt(0) & 0xFFFFFFFF;
            final long size = data >> 13;
            if ((size + 4) > this.buffer.position()) {
                return 0;
            }
            return (int) size + 4;
        } else {
            return this.buffer.getShort(0) + 2;
        }

    }

    @Override
    public byte[] getNextPacket(final int size) {
        this.buffer.limit(this.buffer.position());
        final byte[] data = new byte[size];
        // rewind to read first packet in buffer
        this.buffer.position(0);
        // get the packet header
        this.buffer.get(data);
        this.needDecrypt = true;
        this.buffer.compact();
        return data;
    }

    @Override
    public void addData(final byte[] data) {
        this.buffer.put(data);
    }

    @Override
    public void addData(final PcapPacket packet) {
        final Payload payloadHeader = new Payload();
        if (packet.hasHeader(payloadHeader)) {
            this.buffer.put(payloadHeader.data());
        }
    }

    public static final byte[] intToByteArray(final int value) {
        return new byte[] {
            (byte) (value), (byte) (value >>> 8), (byte) (value >>> 16), (byte) (value >>> 24) };
    }

    public static final int byteArrayToInt(final byte[] value) {
        int res = 0;
        for (final byte element : value) {
            res <<= 8;
            res |= (element & 0xFF);
        }
        return res;
    }

    /**
     * @return the crypt
     */
    @Override
    public final Crypt getCrypt() {
        return this.crypt;
    }

}
