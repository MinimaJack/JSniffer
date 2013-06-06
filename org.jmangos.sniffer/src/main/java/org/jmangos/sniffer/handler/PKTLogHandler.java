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
package org.jmangos.sniffer.handler;

import java.io.DataOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.jmangos.sniffer.enums.Direction;
import org.jmangos.sniffer.jna.WoWKeyReader;
import org.jmangos.sniffer.network.model.NetworkChannel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;

@Component
@Lazy(value = true)
public class PKTLogHandler implements PacketLogHandler {

    private DataOutputStream fous;
    private boolean isInit = false;
    private final Integer build;
    @Autowired
    @Qualifier("WoWKeyReader")
    private WoWKeyReader keyReader;

    public PKTLogHandler(final Integer build) {
        this.build = build;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.jmangos.sniffer.handler.PacketLogHandler#init()
     */
    @Override
    public void init() {
        final String date = String.format("%X", System.currentTimeMillis());
        final ByteBuffer buffer = ByteBuffer.allocate(66);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.put("PKT".getBytes());
        buffer.put((byte) 1);
        buffer.put((byte) 3);
        buffer.put((byte) 12);
        buffer.putInt(this.build);
        buffer.put("xxXX".getBytes());
        buffer.put(this.keyReader.getKey());
        buffer.putInt((int) (System.currentTimeMillis() / 1000L));
        buffer.putInt(0);
        buffer.putInt(0);
        try {
            this.fous =
                    new DataOutputStream(new FileOutputStream(new File(this.build +
                        "_" +
                        date +
                        ".pkt")));
            this.fous.write(buffer.array());
            setInit(true);
        } catch (final FileNotFoundException e) {
            e.printStackTrace();
        } catch (final IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * @return the isInit
     */
    public final boolean isInit() {
        return this.isInit;
    }

    /**
     * @param isInit
     *        the isInit to set
     */
    public final void setInit(final boolean isInit) {
        this.isInit = isInit;
    }

    /**
     * (non-Javadoc)
     * 
     * @see org.jmangos.sniffer.handler.PacketLogHandler#onDecodePacket(org.jmangos
     *      .sniffer.network.model.NetworkChannel,
     *      org.jmangos.sniffer.enums.Direction, java.lang.Integer,
     *      java.lang.Integer, byte[], int)
     */
    @Override
    public void onDecodePacket(final NetworkChannel channel, final Direction direction,
            final Integer size, final Integer opcode, final byte[] data, final int frame) {
        if (!isInit()) {
            init();
        }
        try {
            final ByteBuffer buffer = ByteBuffer.allocate(4 + 4 + 4 + 4 + 4 + data.length + 4);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.put(direction.getValue());
            buffer.putInt(channel.hashCode());
            buffer.putInt(frame);
            buffer.putInt(0);
            buffer.putInt(data.length + 4);
            buffer.putInt(opcode);
            buffer.put(data);
            this.fous.write(buffer.array());
        } catch (final IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * (non-Javadoc)
     * 
     * @see org.jmangos.sniffer.handler.PacketLogHandler#flushAndReset()
     */
    @Override
    public void flushAndReset() {
        try {
            if (this.fous != null) {
                this.fous.flush();
                this.fous.close();
            }
            setInit(false);
        } catch (final IOException e) {
            e.printStackTrace();
        }
    }
}
