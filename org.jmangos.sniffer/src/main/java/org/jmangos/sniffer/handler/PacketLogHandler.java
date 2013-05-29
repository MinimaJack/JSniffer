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
import org.jmangos.sniffer.network.model.NetworkChannel;

public interface PacketLogHandler {

    public abstract void init();

    public abstract void onDecodePacket(NetworkChannel channel, Direction direction, Integer size,
            Integer opcode, byte[] data, int frame);

    public abstract void flushAndReset();

}
