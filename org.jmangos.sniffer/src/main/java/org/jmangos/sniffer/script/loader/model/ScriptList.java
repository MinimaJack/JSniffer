package org.jmangos.sniffer.script.loader.model;

import java.util.List;

import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlAccessType;

import javolution.util.FastList;

@XmlRootElement(name = "DataScripts")
@XmlAccessorType(XmlAccessType.NONE)
public class ScriptList {
    /** The data. */
    public List<ScriptTemplate> data = new FastList<ScriptTemplate>();

    /** The templates. */
    @XmlElement(name = "script")
    private List<ScriptTemplate> templates;

	public List<ScriptTemplate> getTemplates() {
		return templates;
	}

	public void setTemplates(List<ScriptTemplate> templates) {
		this.templates = templates;
	}
    
}
