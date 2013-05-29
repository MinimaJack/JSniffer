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

import java.util.List;
import java.util.Map;

import javolution.util.FastList;
import javolution.util.FastMap;

import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.tcpip.Tcp;

public class TCPPacketBuffer {

    private static final long MODUL = 4294967296L;
    private final Map<Long, SeqHolder> waitingPrevious = new FastMap<Long, SeqHolder>();
    private final List<PcapPacket> sequenced = new FastList<PcapPacket>();
    private long lastAck;

    public TCPPacketBuffer() {

    }

    public void addPacket(final PcapPacket p) {
        long pseq = 0;
        long oseq;
        final Payload pPayload = new Payload();
        final Payload oPayload = new Payload();
        if (p.hasHeader(pPayload) && (pPayload.dataLength() > 0)) {
            final Tcp newTcp = new Tcp();
            p.hasHeader(newTcp);
            for (final SeqHolder sh : this.waitingPrevious.values()) {
                final PcapPacket old = sh.getPacket();
                oseq = sh.getSequence();
                old.hasHeader(oPayload);
                pseq = newTcp.seq();
                if (oseq == pseq) {
                    final byte[] pPayloadData = pPayload.data();
                    final byte[] oPayloadData = oPayload.data();
                    if (oPayloadData.length < pPayloadData.length) {
                        final int diff = pPayloadData.length - oPayloadData.length;
                        final long seq = (oseq + oPayloadData.length) % MODUL;
                        final byte[] data = new byte[diff];
                        System.arraycopy(pPayloadData, pPayloadData.length - diff, data, 0, diff);
                        pPayload.setByteArray(0, data);
                        newTcp.seq(seq);
                    } else if (oPayload.dataLength() == pPayload.dataLength()) {
                        return;
                    }
                }
            }

            final long nextSeq = (pseq + pPayload.size()) % MODUL;

            this.waitingPrevious.put(nextSeq, new SeqHolder(nextSeq, p));
            processAck(this.lastAck);
        }
    }

    public void processAck(final PcapPacket p) {
        final Tcp tcp = new Tcp();
        if (p.hasHeader(tcp)) {
            this.lastAck = tcp.ack();
            processAck(this.lastAck);
        }

    }

    public void processAck(final long ack) {
        final SeqHolder sh = this.waitingPrevious.get(ack);
        if ((sh != null) && !sh.isAcked()) {
            final long previousSeq = sh.getSequence();
            processAck(previousSeq);
            this.addSequenced(ack);
        }
    }

    private void addSequenced(final long ack) {
        final SeqHolder seqHolder = this.waitingPrevious.get(ack);
        seqHolder.ack();
        final PcapPacket packet = seqHolder.getPacket();
        this.addSequenced(packet);
    }

    private void addSequenced(final PcapPacket packet) {
        this.sequenced.add(packet);
    }

    public List<PcapPacket> getSequencedPackets() {
        return this.sequenced;
    }

    public int getPendingSequencePackets() {
        return this.waitingPrevious.size();
    }

    public void flush() {
        this.sequenced.clear();
    }

    public boolean hasSequencedPacket() {
        return (!this.sequenced.isEmpty());
    }
}
