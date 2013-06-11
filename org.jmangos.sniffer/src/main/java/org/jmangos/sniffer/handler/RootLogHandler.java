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

import java.util.Collection;

import javax.annotation.PostConstruct;

import javolution.util.FastList;

import org.jmangos.sniffer.enums.Direction;
import org.jmangos.sniffer.network.model.NetworkChannel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
@Qualifier("RootLogger")
public class RootLogHandler implements PacketLogHandler {
	Logger log = LoggerFactory.getLogger(RootLogHandler.class);
	@Autowired
	@Qualifier("pkt")
	private PacketLogHandler pktLogHandler;
	@Autowired
	@Qualifier("txt")
	private PacketLogHandler txtLogHandler;
	@Value("${sniffer.log.enablePkt}")
	private int pktEnabled;
	@Value("${sniffer.log.enableTxt}")
	private int txtEnabled;

	Collection<PacketLogHandler> logHandlers = new FastList<PacketLogHandler>()
			.shared();

	public RootLogHandler() {
	}

	/**
	 * (non-Javadoc)
	 * 
	 * @see org.jmangos.sniffer.handler.PacketLogHandler#init()
	 */
	@Override
	@PostConstruct
	public void init() {
		if (pktEnabled == 1) {
			logHandlers.add(this.pktLogHandler);
		}
		if (txtEnabled == 1) {
			logHandlers.add(this.txtLogHandler);
		}
	}

	public void addLogHandler(PacketLogHandler handler) {
		logHandlers.add(handler);
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
	public void onDecodePacket(final NetworkChannel channel,
			final Direction direction, final Integer size,
			final Integer opcode, final byte[] data, final int frame) {
		for (PacketLogHandler handler : logHandlers) {
			try {
				handler.onDecodePacket(channel, direction, size, opcode, data,
						frame);
			} catch (Exception e) {
				log.error("Got error on log handler: "
						+ handler.getClass().getCanonicalName(), e);
			}
		}
	}

	/**
	 * (non-Javadoc)
	 * 
	 * @see org.jmangos.sniffer.handler.PacketLogHandler#flushAndReset()
	 */
	@Override
	public void flushAndReset() {
		for (PacketLogHandler handler : logHandlers) {
			try {
				handler.flushAndReset();
			} catch (Exception e) {
				log.error("Got error when flush log handler: "
						+ handler.getClass().getCanonicalName(), e);
			}
		}
	}
}
