package org.jmangos.sniffer.script;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import javax.annotation.PostConstruct;
import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.JavaFileObject.Kind;
import javax.tools.SimpleJavaFileObject;
import javax.tools.ToolProvider;

import org.jmangos.sniffer.handler.PacketLogHandler;
import org.jmangos.sniffer.handler.RootLogHandler;
import org.jmangos.sniffer.script.handler.ScriptHandler;
import org.jmangos.sniffer.script.loader.XMLScriptClassLoader;
import org.jmangos.sniffer.script.loader.impl.ScriptClassLoaderImpl;
import org.jmangos.sniffer.script.loader.model.ScriptTemplate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.stereotype.Service;

@Service
public class JavaScripting implements ApplicationContextAware {
	private ApplicationContext context;
	private static final Logger log = LoggerFactory
			.getLogger(JavaScripting.class);
	@Autowired
	RootLogHandler rootLogger;
	@Autowired
	XMLScriptClassLoader xmlScriptClassLoader;

	@PostConstruct
	public void compile() throws IOException, NoSuchMethodException,
			SecurityException, InstantiationException, IllegalAccessException,
			IllegalArgumentException {
		JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
		DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<JavaFileObject>();
		ClassFileManager clfm;
		try {
			clfm = new ClassFileManager(compiler, diagnostics);
		} catch (Exception e) {
			log.info("Scripts not loaded. Need JDK for loading.");
			return;
		}

		ScriptClassLoaderImpl sl = new ScriptClassLoaderImpl(clfm,
				context.getClassLoader());
		clfm.setLoader(sl);
		xmlScriptClassLoader.loadPacket();
		List<ScriptTemplate> scripts = xmlScriptClassLoader.getScripts();
		if (scripts == null) {
			return;
		}
		List<SimpleJavaFileObject> ulist = new ArrayList<>();
		for (ScriptTemplate scriptTemplate : xmlScriptClassLoader.getScripts()) {
			JavaFileSource cuy = new JavaFileSource(new File(
					scriptTemplate.getPath()), Kind.SOURCE);
			ulist.add(cuy);
		}
		JavaCompiler.CompilationTask task = compiler.getTask(null, clfm,
				diagnostics, null, null, ulist);
		Boolean success = task.call();
		for (Diagnostic<? extends JavaFileObject> scriptT : diagnostics
				.getDiagnostics()) {
			log.error(scriptT.getSource().getName() + " line: "
					+ scriptT.getLineNumber() + " "
					+ scriptT.getMessage(Locale.getDefault()));
		}

		for (ScriptTemplate scriptTemplate : xmlScriptClassLoader.getScripts()) {
			try {
				if (success) {
					Class<?> clazz = sl.loadClass(scriptTemplate.getName());
					Object o = clazz.newInstance();
					context.getAutowireCapableBeanFactory().autowireBean(o);
					if (o instanceof PacketLogHandler) {
						rootLogger.addLogHandler((PacketLogHandler) o);
					}
					if (o instanceof ScriptHandler) {
						((ScriptHandler) o).initScript();
					}
					if (o instanceof Runnable) {
						new Thread((Runnable) o).run();
					}
				}
			} catch (ClassNotFoundException e) {

			}

		}

		clfm.close();

	}

	@Override
	public void setApplicationContext(ApplicationContext context)
			throws BeansException {
		this.context = context;

	}
}
