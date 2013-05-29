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
package org.jmangos.sniffer.network.model;

import java.util.EnumSet;
import java.util.List;

import org.jmangos.sniffer.enums.State;
import org.jmangos.sniffer.handler.PacketLogHandler;
import org.jnetpcap.packet.PcapPacket;

/**
 * The Interface NetworkChannel.
 */
public interface NetworkChannel {

    /**
     * Gets the channel id.
     * 
     * @return unique ID for context's channel
     */
    String getChannelId();

    /**
     * @param channelId
     *        the channelId to set
     */
    void setChannelId(final String channelId);

    /**
     * Gets the channel state.
     * 
     * @return channel state
     */
    EnumSet<State> getChannelState();

    /**
     * Sets the channel state.
     * 
     * @param channelState
     *        the new channel state
     */
    void addChannelState(State channelState);

    /**
     * Checks if is connected.
     * 
     * @return true, if is connected
     */
    boolean isConnected();

    void onResiveServerData(long frameNumber, byte[] buffer);

    void onResiveClientData(long frameNumber, byte[] buffer);

    boolean haveChannelState(State channelState);

    void onResiveServerData(PcapPacket packet, long frameNumber);

    void onResiveClientData(PcapPacket packet, long frameNumber);

    void setClientSeed(byte[] hexStringToByteArray);

    void setServerSeed(byte[] hexStringToByteArray);

    void addLogHandler(PacketLogHandler logHandler);

    List<PacketLogHandler> getPacketLoggers();
}
