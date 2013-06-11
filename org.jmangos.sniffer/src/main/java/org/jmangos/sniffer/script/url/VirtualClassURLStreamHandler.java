package org.jmangos.sniffer.script.url;

import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;

import org.jmangos.sniffer.script.loader.ScriptClassLoader;

public class VirtualClassURLStreamHandler extends URLStreamHandler {
	public static final String HANDLER_PROTOCOL = "snifferscript://";

	private final ScriptClassLoader cl;

	public VirtualClassURLStreamHandler(ScriptClassLoader cl) {
		this.cl = cl;
	}

	@Override
	protected URLConnection openConnection(URL u) throws IOException {
		return new VirtualClassURLConnection(u, cl);
	}
}