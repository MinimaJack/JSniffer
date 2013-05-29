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
package org.jmangos.sniffer.network.decoder;

import java.util.Map;

import org.jmangos.sniffer.network.model.NetworkChannel;

/**
 * @author MinimaJack
 * 
 */
public interface Decoder {

    void onConnect(String sessionHash);

    void onDisconnect(String sessionHash);

    Map<String, NetworkChannel> getNetworkChannels();

}
