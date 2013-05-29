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

import org.jmangos.sniffer.crypt.Crypt;
import org.jnetpcap.packet.PcapPacket;

public interface PacketBuffer {

    /**
     * @return the size in bytes of the data or 0
     */
    public int nextAvaliablePacket();

    /**
     * 
     * @param header
     * @param data
     * @return
     */
    public byte[] getNextPacket(int size);

    /**
     * @param data
     */
    public void addData(byte[] data);

    public void addData(PcapPacket packet);

    /**
     * @return the crypt
     */
    public Crypt getCrypt();

}
