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
package org.jmangos.sniffer.network.decoder.impl;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.PostConstruct;

import org.jmangos.sniffer.enums.State;
import org.jmangos.sniffer.handler.PacketLogHandler;
import org.jmangos.sniffer.handler.RawPacketHandler;
import org.jmangos.sniffer.handler.RootLogHandler;
import org.jmangos.sniffer.network.decoder.Decoder;
import org.jmangos.sniffer.network.model.NetworkChannel;
import org.jmangos.sniffer.utils.HexUtil;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapIf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.stereotype.Service;

/**
 * @author MinimaJack
 * 
 */
@Service
public class DecoderImpl implements Decoder, ApplicationContextAware, Runnable {

	Logger log = LoggerFactory.getLogger(DecoderImpl.class);

	private final HashMap<String, NetworkChannel> activeChannels = new HashMap<String, NetworkChannel>();

	private final List<NetworkChannel> finishedSession = new ArrayList<NetworkChannel>();

	@Autowired
	RawPacketHandler rawHandler;
	@Autowired
	RootLogHandler logHandler;
	@Value("${sniffer.clientSeed}")
	private String clientSeed;
	@Value("${sniffer.serverSeed}")
	private String serverSeed;
	@Value("${sniffer.networkDeviceIndex}")
	private int deviceIndex;

	private ApplicationContext context;

	@PostConstruct
	public void init() {
		Thread th = new Thread(this);
		th.start();
	}

	public void encode() {
		final List<PcapIf> alldevs = new ArrayList<PcapIf>();
		final StringBuilder errbuf = new StringBuilder();
		Pcap.findAllDevs(alldevs, errbuf);
		if (alldevs.isEmpty()) {
			this.log.error("Can't read list of devices, error is {}",
					errbuf.toString());
			return;
		}
		for (int i = 0; i < alldevs.size(); i++) {
			this.log.info("Network device: {} ", alldevs.get(i).getAddresses()
					.get(0).getAddr());
		}
		if ((this.deviceIndex - 1) > alldevs.size()) {
			this.log.error(
					"Network device number to big. Exist devices: {}, configurated as: {}.\n Try to set sniffer.networkDeviceIndex to lower value.",
					alldevs.size(), this.deviceIndex);
			System.exit(1);
			return;
		}
		log.info("Selected device: {}", alldevs.get(deviceIndex).getAddresses()
				.get(0).getAddr());
		final PcapIf device = alldevs.get(this.deviceIndex);
		final PcapBpfProgram program = new PcapBpfProgram();
		final String expression = "port 3724";
		final int optimize = 1;
		/** mask 255.255.255.0 */
		final int netmask = 0xFFFFFF00;

		final int snaplen = 64 * 1024;
		final int flags = Pcap.MODE_PROMISCUOUS;
		final int timeout = 10 * 1000;
		final Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags,
				timeout, errbuf);
		if (pcap == null) {
			this.log.error("Error while opening device for capture: {}",
					errbuf.toString());
			return;
		}
		if (pcap.compile(program, expression, optimize, netmask) != Pcap.OK) {
			this.log.error(pcap.getErr());
			return;
		}
		if (pcap.setFilter(program) != Pcap.OK) {
			this.log.error(pcap.getErr());
			return;
		}
		try {
			while (pcap.loop(Pcap.LOOP_INFINITE, this.rawHandler, this) == Pcap.OK) {
				;
				;
			}
		} finally {
			pcap.close();
		}

	}

	/**
	 * @return the sessions
	 */
	@Override
	public final Map<String, NetworkChannel> getNetworkChannels() {
		return this.activeChannels;
	}

	@Override
	public void onConnect(final String channelHash) {
		if (this.activeChannels.containsKey(channelHash)) {
			return;
		}
		final NetworkChannel channel = this.context
				.getBean(NetworkChannel.class);
		channel.setChannelId(channelHash);
		channel.addChannelState(State.CONNECTED);
		if (this.activeChannels.size() == 0) {
			channel.addChannelState(State.NOT_ACCEPT_SEED);
			channel.setClientSeed(HexUtil.hexStringToByteArray(this.clientSeed));
			channel.setServerSeed(HexUtil.hexStringToByteArray(this.serverSeed));
		}
		channel.addLogHandler(logHandler);
		this.activeChannels.put(channelHash, channel);
	}

	@Override
	public void onDisconnect(final String channelHash) {

		if (this.activeChannels.containsKey(channelHash)) {
			final NetworkChannel savedSession = this.activeChannels
					.get(channelHash);
			savedSession.addChannelState(State.DISCONNECTED);
			this.finishedSession.add(savedSession);
			this.activeChannels.remove(channelHash);
			if (this.activeChannels.size() == 0) {
				for (final PacketLogHandler logger : savedSession
						.getPacketLoggers()) {
					logger.flushAndReset();
				}
			}
		}
	}

	@Override
	public void setApplicationContext(final ApplicationContext context)
			throws BeansException {
		this.context = context;

	}

	@Override
	public void run() {
		encode();

	}
}
