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

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * The Class Crypt.
 */
public class Crypt {

    byte[] encryptionKey;

    /** The is enabled. */
    private boolean isEnabled = false;

    /**
     * @return the isEnabled
     */
    public final boolean isEnabled() {
        return this.isEnabled;

    }

    /**
     * @param isEnabled
     *        the isEnabled to set
     */
    public final void setEnabled(final boolean isEnabled) {
        this.isEnabled = isEnabled;
    }

    /** The _client decrypt. */
    private final SARC4 clientDecryptSARC4 = new SARC4();

    /**
     * Instantiates a new crypt.
     */
    public Crypt() {

    }

    /**
     * Decrypt.
     * 
     * @param data
     *        the data
     * @return the byte[]
     */
    public byte[] decrypt(final byte[] data) {

        if (!this.isEnabled) {
            System.out.println("Crypt not enable");
            return data;

        }
        return this.clientDecryptSARC4.update(data);
    }

    /**
     * Init crypto-system.
     * 
     * @param key
     *        is seed
     */
    public void init(final byte[] key) {

        final byte[] encryptHash = getKey(this.encryptionKey, key);
        this.clientDecryptSARC4.init(encryptHash);

        final byte[] tar = new byte[1024];
        for (int i = 0; i < tar.length; i++) {
            tar[i] = 0;
        }
        this.clientDecryptSARC4.update(tar);
        this.isEnabled = true;
    }

    /**
     * Gets the encryption key.
     * 
     * @param EncryptionKey
     *        the encryption key
     * @param key
     *        the key
     * @return the key
     */
    private byte[] getKey(final byte[] EncryptionKey, final byte[] key) {

        final SecretKeySpec ds = new SecretKeySpec(EncryptionKey, "HmacSHA1");
        Mac m;
        try {
            m = Mac.getInstance("HmacSHA1");
            m.init(ds);
            return m.doFinal(key);
        } catch (final Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * @return the serverEncryptionKey
     */
    public final byte[] getServerEncryptionKey() {
        return this.encryptionKey;
    }

    /**
     * @param serverEncryptionKey
     *        the serverEncryptionKey to set
     */
    public final void setEncryptionSeed(final byte[] serverEncryptionKey) {
        this.encryptionKey = serverEncryptionKey;
    }

}
