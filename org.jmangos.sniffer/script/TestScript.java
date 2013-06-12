package org.rumangos.sniffer;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.Timer;

import org.jmangos.sniffer.enums.Direction;
import org.jmangos.sniffer.handler.PacketLogHandler;
import org.jmangos.sniffer.network.model.NetworkChannel;
import org.jmangos.sniffer.script.handler.ScriptHandler;
import org.springframework.beans.factory.annotation.Value;

public class TestScript implements ScriptHandler, Runnable {
	@Value("${sniffer.build}")
	private Integer build;
	JLabel label;
	boolean init = false;
	int countPackets = 0;
	private Timer timer;


	@Override
	public void initScript() {
		System.out.println("Test script initialization");
	}

	@Override
	public void run() {
		for (int i = 0; i < 5; i++) {
			System.out.println("times: " + i + ". Systemtime:" + System.currentTimeMillis());
			try {
				Thread.sleep(1000L);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}
		
	}
}
