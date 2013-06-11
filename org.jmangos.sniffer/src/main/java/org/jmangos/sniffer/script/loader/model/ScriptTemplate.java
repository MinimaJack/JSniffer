package org.jmangos.sniffer.script.loader.model;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;

@XmlAccessorType(XmlAccessType.FIELD)
public class ScriptTemplate {
	  /** The script id. */
    @XmlAttribute(name = "id", required = true)
    private String scriptId;

    /** The name. */
    @XmlAttribute(name = "name", required = true)
    private String name;

    /** The path. */
    @XmlAttribute(name = "path", required = true)
    private String path;

    private boolean success = false;
    
	public String getScriptId() {
		return scriptId;
	}

	public void setScriptId(String scriptId) {
		this.scriptId = scriptId;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getPath() {
		return path;
	}

	public void setPath(String path) {
		this.path = path;
	}

	public boolean isSuccess() {
		return success;
	}

	public void setSuccess(boolean success) {
		this.success = success;
	}



}
