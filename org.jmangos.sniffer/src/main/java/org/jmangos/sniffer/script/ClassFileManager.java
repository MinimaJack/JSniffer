package org.jmangos.sniffer.script;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.tools.DiagnosticListener;
import javax.tools.FileObject;
import javax.tools.ForwardingJavaFileManager;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileManager;
import javax.tools.JavaFileObject;
import javax.tools.JavaFileObject.Kind;
import javax.tools.StandardLocation;

import org.jmangos.sniffer.script.loader.ScriptClassLoader;
import org.jmangos.sniffer.script.loader.impl.ScriptClassLoaderImpl;

public class ClassFileManager extends
		ForwardingJavaFileManager<JavaFileManager> {
	/**
	 * This map contains classes compiled for this classloader
	 */
	private final Map<String, BinaryClassWrapper> compiledClasses = new HashMap<String, BinaryClassWrapper>();

	protected ScriptClassLoader loader;

	public ScriptClassLoader getLoader() {
		return loader;
	}

	public void setLoader(ScriptClassLoader loader) {
		this.loader = loader;
	}

	protected ClassLoader parentClassLoader;

	public ClassFileManager(JavaCompiler compiler,
			DiagnosticListener<? super JavaFileObject> listener) {
		super(compiler.getStandardFileManager(listener, null, null));
	}

	@Override
	public JavaFileObject getJavaFileForOutput(Location location,
			String className, Kind kind, FileObject sibling) throws IOException {
		BinaryClassWrapper co = new BinaryClassWrapper(className);
		compiledClasses.put(className, co);
		return co;
	}

	@Override
	public synchronized ScriptClassLoaderImpl getClassLoader(Location location) {
		if (loader == null) {
			if (parentClassLoader != null) {
				loader = new ScriptClassLoaderImpl(this, parentClassLoader);
			} else {
				loader = new ScriptClassLoaderImpl(this);
			}
		}
		return (ScriptClassLoaderImpl) loader;
	}

	public Map<String, BinaryClassWrapper> getCompiledClasses() {
		return compiledClasses;
	}

	@Override
	public Iterable<JavaFileObject> list(Location location, String packageName,
			Set<Kind> kinds, boolean recurse) throws IOException {
		Iterable<JavaFileObject> objects = super.list(location, packageName,
				kinds, recurse);

		if (StandardLocation.CLASS_PATH.equals(location)
				&& kinds.contains(Kind.CLASS)) {
			List<JavaFileObject> temp = new ArrayList<JavaFileObject>();
			for (JavaFileObject object : objects) {
				temp.add(object);
			}
			temp.addAll(loader.getClassesForPackage(packageName));
			objects = temp;
		}

		return objects;
	}
}