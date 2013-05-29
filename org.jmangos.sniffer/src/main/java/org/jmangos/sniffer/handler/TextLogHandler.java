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

import org.jmangos.sniffer.enums.Direction;
import org.jmangos.sniffer.network.model.NetworkChannel;
import org.jmangos.sniffer.utils.HexUtil;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;

@Component
@Lazy(value = true)
public class TextLogHandler implements PacketLogHandler {

    private DataOutputStream fous;
    private boolean isInit = false;
    private final Integer build;

    public TextLogHandler(final Integer build) {
        this.build = build;
    }

    /**
     * (non-Javadoc)
     * 
     * @see org.jmangos.sniffer.handler.PacketLogHandler#init()
     */
    @Override
    public void init() {
        final String date = String.format("%X", System.currentTimeMillis());
        try {
            this.fous =
                    new DataOutputStream(new FileOutputStream(new File(this.build +
                        "_" +
                        date +
                        ".dmp")));
            setInit(true);
        } catch (final FileNotFoundException e) {
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
            this.fous.write(String.format("Time: %d;OpcodeType: %s;OpcodeValue: 0x%x; Packet: ",
                    frame, (direction.equals(Direction.CLIENT) ? "CMSG" : "SMSG"), opcode).getBytes());
            this.fous.write(HexUtil.bytesToHex(data).getBytes());
            this.fous.write("\n".getBytes());
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
