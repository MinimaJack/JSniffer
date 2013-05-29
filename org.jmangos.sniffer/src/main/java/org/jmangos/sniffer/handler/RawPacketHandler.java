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

import org.jmangos.sniffer.enums.Direction;
import org.jmangos.sniffer.enums.State;
import org.jmangos.sniffer.network.decoder.Decoder;
import org.jmangos.sniffer.network.model.NetworkChannel;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * @author MinimaJack
 * 
 */
@Component
public class RawPacketHandler implements PcapPacketHandler<Decoder> {

    private final Logger log = LoggerFactory.getLogger(RawPacketHandler.class);
    private final Tcp tcp = new Tcp();
    private final Ip4 ip = new Ip4();
    private Direction direction;

    @Override
    public void nextPacket(final PcapPacket packet, final Decoder decoder) {

        if (!(packet.hasHeader(this.ip) && packet.hasHeader(this.tcp)) &&
            (!((this.tcp.source() == 3724) || (this.tcp.destination() == 3724)))) {
            return;
        }
        this.direction = (this.tcp.source() == 3724) ? Direction.SERVER : Direction.CLIENT;
        final String sessionHash = getSessionHash();
        if (this.tcp.flags_SYN() && this.direction.equals(Direction.CLIENT)) {
            decoder.onConnect(sessionHash);
        }
        final NetworkChannel cursession = decoder.getNetworkChannels().get(sessionHash);
        if (cursession == null) {
            return;
        }
        this.log.debug("Current session: {} {} ", cursession.getChannelId(),
                cursession.getChannelState().contains(State.AUTHED) ? "AUTHED" : "CONNECTED");
        if (this.direction.equals(Direction.SERVER)) {
            cursession.onResiveServerData(packet, packet.getFrameNumber());
        } else {
            cursession.onResiveClientData(packet, packet.getFrameNumber());
        }
        if (this.tcp.flags_FIN() && this.direction.equals(Direction.SERVER)) {
            this.log.info("Close Connection: " + sessionHash);
            decoder.onDisconnect(sessionHash);
        }
    }

    private String getSessionHash() {
        final StringBuilder sb = new StringBuilder();
        byte[] s;
        byte[] d;
        int sp = 0;
        int dp;
        if (this.direction.equals(Direction.SERVER)) {
            s = this.ip.source();
            d = this.ip.destination();
            sp = this.tcp.source();
            dp = this.tcp.destination();
        } else {
            s = this.ip.destination();
            d = this.ip.source();
            sp = this.tcp.destination();
            dp = this.tcp.source();
        }
        sb.append(s[0] & 0xFF).append(".").append(s[1] & 0xFF).append(".").append(s[2] & 0xFF).append(
                ".").append(s[3] & 0xFF);
        sb.append(" ").append(sp);
        sb.append("-");
        sb.append(d[0] & 0xFF).append(".").append(d[1] & 0xFF).append(".").append(d[2] & 0xFF).append(
                ".").append(d[3] & 0xFF);
        sb.append(" ").append(dp);
        return sb.toString();
    }
}
