package org.jmangos.sniffer.dataholders;

import java.io.File;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;

/**
 * The Class XmlDataLoader.
 * 
 */
public class XmlDataLoader {
	Logger log = LoggerFactory.getLogger(XmlDataLoader.class);

	/**
	 * Load static data.
	 * 
	 * @param <T>
	 * @param clazz
	 * @param Schema
	 * @param XmlFile
	 * @return
	 */
	public <T> T loadStaticData(final Class<T> clazz, final String Schema,
			final String XmlFile) {

		try {
			final JAXBContext jc = JAXBContext.newInstance(clazz);
			final Unmarshaller un = jc.createUnmarshaller();
			un.setSchema(getSchema(Schema));
			return clazz.cast(un.unmarshal(new File(XmlFile)));
		} catch (final Exception e) {
			log.error("Error while loading xml data for class: {} with path: {}",
					clazz.getCanonicalName(), XmlFile);
		}
		return null;
	}

	public <T> T loadStaticData(final Class<T> clazz, final String XmlFile) {

		try {
			final JAXBContext jc = JAXBContext.newInstance(clazz);
			final Unmarshaller un = jc.createUnmarshaller();
			return clazz.cast(un.unmarshal(new File(XmlFile)));
		} catch (final Exception e) {
			log.error("Error while loading xml data for class:{} with path: {} ",
					clazz.getCanonicalName(), XmlFile);
		}
		return null;
	}

	/**
	 * Gets the schema.
	 * 
	 * @param Schema
	 *            the schema
	 * @return the schema
	 */
	private static Schema getSchema(final String Schema) {

		final SchemaFactory sf = SchemaFactory
				.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
		Schema schema = null;
		try {
			schema = sf.newSchema(new File(Schema));
		} catch (final SAXException e) {
			System.err.println("Error getting schema");
			e.printStackTrace();
		}

		return schema;
	}
}
