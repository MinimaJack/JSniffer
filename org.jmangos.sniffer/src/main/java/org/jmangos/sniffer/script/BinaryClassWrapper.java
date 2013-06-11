package org.jmangos.sniffer.script;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.io.Writer;
import java.net.URI;

import javax.lang.model.element.Modifier;
import javax.lang.model.element.NestingKind;
import javax.tools.JavaFileObject;

public class BinaryClassWrapper implements JavaFileObject {

	/**
	 * ClassName
	 */
	private final String name;

	/**
	 * Class data will be written here
	 */
	private final ByteArrayOutputStream baos = new ByteArrayOutputStream();

	private Class<?> definedClass;

	public BinaryClassWrapper(String name) {
		this.name = name;
	}

	public URI toUri() {
		throw new UnsupportedOperationException();
	}

	public String getName() {
		return name + ".class";
	}

	public InputStream openInputStream() throws IOException {
		return new ByteArrayInputStream(baos.toByteArray());
	}

	public OutputStream openOutputStream() throws IOException {
		return baos;
	}

	public CharSequence getCharContent(boolean ignoreEncodingErrors)
			throws IOException {
		throw new UnsupportedOperationException();
	}

	public Writer openWriter() throws IOException {
		throw new UnsupportedOperationException();
	}

	public long getLastModified() {
		return 0;
	}

	public boolean delete() {
		return false;
	}

	protected String inferBinaryName(Iterable<? extends File> path) {
		return name;
	}

	public boolean isNameCompatible(String simpleName, Kind kind) {
		return Kind.CLASS.equals(kind);
	}

	public byte[] getBytes() {
		return baos.toByteArray();
	}

	public Class<?> getDefinedClass() {
		return definedClass;
	}

	public void setDefinedClass(Class<?> definedClass) {
		this.definedClass = definedClass;
	}

	@Override
	public Reader openReader(boolean ignoreEncodingErrors) throws IOException {
		return null;
	}

	@Override
	public Kind getKind() {
		return null;
	}

	@Override
	public NestingKind getNestingKind() {
		return null;
	}

	@Override
	public Modifier getAccessLevel() {
		return null;
	}
}