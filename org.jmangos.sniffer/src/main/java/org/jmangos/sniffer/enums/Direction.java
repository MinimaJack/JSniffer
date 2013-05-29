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
package org.jmangos.sniffer.enums;

/**
 * @author MinimaJack
 * 
 */
public enum Direction {
    CLIENT("CMSG"),
    SERVER("SMSG");

    private final byte[] value;

    Direction(final String data) {
        this.value = data.getBytes();
    }

    /**
     * @return the value
     */
    public final byte[] getValue() {
        return this.value;
    }
}
