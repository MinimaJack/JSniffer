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
package org.jmangos.sniffer.jna;

public interface Kernel32 extends com.sun.jna.platform.win32.Kernel32 {

    public final static int PROCESS_QUERY_INFORMATION = 0x0400;
    public final static int PROCESS_VM_READ = 0x0010;
    public final static int PROCESS_VM_WRITE = 0x0020;
    public final static int PROCESS_VM_OPERATION = 0x0008;
}
