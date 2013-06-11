package org.jmangos.sniffer.script;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import javax.tools.SimpleJavaFileObject;

import sun.misc.IOUtils;

public class JavaFileSource extends SimpleJavaFileObject {
	public JavaFileSource(File file, Kind kind) {
		super(file.toURI(), kind);
	}

	@Override
	public CharSequence getCharContent(boolean ignoreEncodingErrors)
			throws IOException {

		return new String(IOUtils.readFully(
				new FileInputStream(new File(this.toUri())), Integer.MAX_VALUE,
				true));
	}
}
