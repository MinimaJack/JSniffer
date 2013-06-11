package org.jmangos.sniffer.script.loader.impl;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import javax.tools.JavaFileObject;

import org.jmangos.sniffer.script.BinaryClassWrapper;
import org.jmangos.sniffer.script.ClassFileManager;
import org.jmangos.sniffer.script.loader.ScriptClassLoader;
import org.jmangos.sniffer.utils.ClassUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ScriptClassLoaderImpl extends ScriptClassLoader {

	/**
	 * Logger
	 */
	private static final Logger log = LoggerFactory
			.getLogger(ScriptClassLoaderImpl.class);
	private final ClassFileManager classFileManager;

	public ScriptClassLoaderImpl(ClassFileManager classFileManager) {
		super(new URL[] {});
		this.classFileManager = classFileManager;
	}

	public ScriptClassLoaderImpl(ClassFileManager classFileManager,
			ClassLoader parent) {
		super(new URL[] {}, parent);
		this.classFileManager = classFileManager;
	}

	public ClassFileManager getClassFileManager() {
		return classFileManager;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Set<String> getCompiledClasses() {
		Set<String> compiledClasses = classFileManager.getCompiledClasses()
				.keySet();
		return Collections.unmodifiableSet(compiledClasses);
	}

	@Override
	public Set<JavaFileObject> getClassesForPackage(String packageName)
			throws IOException {
		Set<JavaFileObject> result = new HashSet<JavaFileObject>();

		// load parent
		ClassLoader parent = getParent();
		if (parent instanceof ScriptClassLoaderImpl) {
			@SuppressWarnings("resource")
			ScriptClassLoaderImpl pscl = (ScriptClassLoaderImpl) parent;
			result.addAll(pscl.getClassesForPackage(packageName));
		}

		// load current classloader compiled classes
		for (String cn : classFileManager.getCompiledClasses().keySet()) {
			if (ClassUtils.isPackageMember(cn, packageName)) {
				BinaryClassWrapper bc = classFileManager.getCompiledClasses()
						.get(cn);
				result.add(bc);
			}
		}

		// load libraries
		for (String cn : libraryClasses) {
			if (ClassUtils.isPackageMember(cn, packageName)) {
				BinaryClassWrapper bc = new BinaryClassWrapper(cn);
				try {
					byte[] data = getRawClassByName(cn);
					OutputStream os = bc.openOutputStream();
					os.write(data);
				} catch (IOException e) {
					log.error("Error while loading class from package "
							+ packageName, e);
					throw e;
				}
				result.add(bc);
			}
		}

		return result;
	}

	protected byte[] getRawClassByName(String name) throws IOException {
		URL resource = findResource(name.replace('.', '/').concat(".class"));
		InputStream is = null;
		byte[] clazz = null;

		try {
			is = resource.openStream();
			clazz = sun.misc.IOUtils.readFully(is, Integer.MAX_VALUE, true);
		} catch (IOException e) {
			log.error("Error while loading class data", e);
			throw e;
		} finally {
			if (is != null) {
				try {
					is.close();
				} catch (IOException e) {
					log.error("Error while closing stream", e);
				}
			}
		}
		return clazz;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public byte[] getByteCode(String className) {
		BinaryClassWrapper bc = getClassFileManager().getCompiledClasses().get(
				className);
		byte[] b = new byte[bc.getBytes().length];
		System.arraycopy(bc.getBytes(), 0, b, 0, b.length);
		return b;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Class<?> getDefinedClass(String name) {
		BinaryClassWrapper bc = classFileManager.getCompiledClasses().get(name);
		if (bc == null) {
			return null;
		}

		return bc.getDefinedClass();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void setDefinedClass(String name, Class<?> clazz) {
		BinaryClassWrapper bc = classFileManager.getCompiledClasses().get(name);

		if (bc == null) {
			throw new IllegalArgumentException(
					"Attempt to set defined class for class that was not compiled?");
		}

		bc.setDefinedClass(clazz);
	}

}
