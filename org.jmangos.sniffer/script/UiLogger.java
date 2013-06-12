package org.rumangos.sniffer;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.Timer;

import org.jmangos.sniffer.enums.Direction;
import org.jmangos.sniffer.handler.PacketLogHandler;
import org.jmangos.sniffer.network.model.NetworkChannel;
import org.springframework.beans.factory.annotation.Value;

public class UiLogger implements PacketLogHandler {
	@Value("${sniffer.build}")
	private Integer build;
	JLabel label;
	boolean init = false;
	int countPackets = 0;
	private Timer timer;

	@Override
	public void init() {
		JFrame frame = new JFrame("Sniffer: MoP. Build: " + build);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.setLocationRelativeTo(null);
		label = new JLabel("Count packets: 0");
		frame.add(label);
		frame.pack();
		frame.setVisible(true);
		init = true;
		timer = new Timer(1000, new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				updateLabel();
			}
		});
	}

	private void updateLabel() {
		label.setText("Count packets: " + countPackets);
	}

	@Override
	public void onDecodePacket(NetworkChannel channel, Direction direction,
			Integer size, Integer opcode, byte[] data, int frame) {
		countPackets++;
		if (!init) {
			synchronized (this) {
				init();
				timer.start();
			}
		}
	}

	@Override
	public void flushAndReset() {

	}
}
