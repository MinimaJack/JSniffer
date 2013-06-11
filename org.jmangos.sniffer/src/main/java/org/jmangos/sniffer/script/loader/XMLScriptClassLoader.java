package org.jmangos.sniffer.script.loader;

import java.util.List;

import org.jmangos.sniffer.dataholders.XmlDataLoader;
import org.jmangos.sniffer.script.loader.model.ScriptList;
import org.jmangos.sniffer.script.loader.model.ScriptTemplate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class XMLScriptClassLoader extends XmlDataLoader {
	private static final Logger log = LoggerFactory
			.getLogger(XMLScriptClassLoader.class);
	@Value("${sniffer.scriptDir}")
	private String scriptPath;
	private ScriptList scripts;

	public void loadPacket() {
		try {
			this.scripts = loadStaticData(ScriptList.class, this.scriptPath);
			if (this.scripts != null)
				for (ScriptTemplate scr : scripts.getTemplates()) {
					log.info("Loaded script defenition [ {} ]",
							scr.getScriptId());
				}
		} catch (Exception e) {
			log.error("Error loading scripts");
		}

	}

	public String getScriptPath() {
		return scriptPath;
	}

	public void setScriptPath(String scriptPath) {
		this.scriptPath = scriptPath;
	}

	public List<ScriptTemplate> getScripts() {
		if (scripts == null) {
			return null;
		}
		return scripts.getTemplates();
	}

	public void setScripts(ScriptList scripts) {
		this.scripts = scripts;
	}

}
