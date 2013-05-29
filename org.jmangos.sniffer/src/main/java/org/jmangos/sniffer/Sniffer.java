/*******************************************************************************
 * Copyright (c) 2013 MinimaJack
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser Public License v2.1
 * which accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 * 
 * Contributors:
 *     MinimaJack - initial API and implementation
 ******************************************************************************/
package org.jmangos.sniffer;

import org.springframework.context.support.ClassPathXmlApplicationContext;

public class Sniffer {

    /**
     * Main startup method
     * 
     * @param args
     *        ignored
     */
    @SuppressWarnings("resource")
    public static void main(final String[] args) {
        new ClassPathXmlApplicationContext(
                new String[] { "classpath:/META-INF/applicationContext.xml" });
    }
}
