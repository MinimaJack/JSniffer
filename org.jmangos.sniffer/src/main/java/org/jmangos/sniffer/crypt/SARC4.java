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
package org.jmangos.sniffer.crypt;

/**
 * The Class SARC4.
 */
public class SARC4 {

    /** The state. */
    private final byte state[] = new byte[256];

    /** The x. */
    private int x;

    /** The y. */
    private int y;

    /**
     * Init by seed.
     * 
     * @param key
     *        - seed
     * @return true, if successful
     */
    public boolean init(final byte[] key) {

        for (int i = 0; i < 256; i++) {
            this.state[i] = (byte) i;
        }

        this.x = 0;
        this.y = 0;

        int index1 = 0;
        int index2 = 0;

        byte tmp;

        if ((key == null) || (key.length == 0)) {
            throw new NullPointerException();
        }

        for (int i = 0; i < 256; i++) {

            index2 = ((key[index1] & 0xff) + (this.state[i] & 0xff) + index2) & 0xff;

            tmp = this.state[i];
            this.state[i] = this.state[index2];
            this.state[index2] = tmp;

            index1 = (index1 + 1) % key.length;
        }
        return true;

    }

    /**
     * Update.
     * 
     * @param buf
     *        the buf
     * @return the byte[]
     */
    public byte[] update(final byte[] buf) {

        int xorIndex;
        byte tmp;

        if (buf == null) {
            return null;
        }

        final byte[] result = new byte[buf.length];

        for (int i = 0; i < buf.length; i++) {

            this.x = (this.x + 1) & 0xff;
            this.y = ((this.state[this.x] & 0xff) + this.y) & 0xff;

            tmp = this.state[this.x];
            this.state[this.x] = this.state[this.y];
            this.state[this.y] = tmp;

            xorIndex = ((this.state[this.x] & 0xff) + (this.state[this.y] & 0xff)) & 0xff;
            result[i] = (byte) (buf[i] ^ this.state[xorIndex]);
        }

        return result;
    }
}
