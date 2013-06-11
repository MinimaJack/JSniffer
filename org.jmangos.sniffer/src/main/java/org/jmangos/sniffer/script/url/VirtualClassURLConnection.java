package org.jmangos.sniffer.script.url;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;

import org.jmangos.sniffer.script.loader.ScriptClassLoader;

public class VirtualClassURLConnection extends URLConnection {
	private InputStream is;

	protected VirtualClassURLConnection(URL url, ScriptClassLoader cl) {
		super(url);
		is = new ByteArrayInputStream(cl.getByteCode(url.getHost()));
	}

	@Override
	public void connect() throws IOException {
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public InputStream getInputStream() throws IOException {
		return is;
	}
}