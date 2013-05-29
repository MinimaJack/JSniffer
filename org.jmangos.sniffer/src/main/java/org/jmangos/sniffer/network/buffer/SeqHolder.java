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
package org.jmangos.sniffer.network.buffer;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.tcpip.Tcp;

public class SeqHolder {

    private final long nextSeq;
    private final long sequence;
    private final PcapPacket packet;
    private boolean isAcked;

    public SeqHolder(final long nextSeq, final PcapPacket packet) {
        this.nextSeq = nextSeq;
        this.packet = packet;
        final Tcp tcp = new Tcp();
        packet.hasHeader(tcp);
        this.sequence = tcp.seq();
    }

    /**
     * @return the nextSeq
     */
    public long getNextSeq() {
        return this.nextSeq;
    }

    /**
     * @return the packet
     */
    public PcapPacket getPacket() {
        return this.packet;
    }

    public void ack() {
        this.isAcked = true;
    }

    /**
     * 
     * @return true if asked
     */
    public boolean isAcked() {
        return this.isAcked;
    }

    /**
     * @return the sequence
     */
    public long getSequence() {
        return this.sequence;
    }

}
