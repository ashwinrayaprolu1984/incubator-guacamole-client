package org.apache.guacamole.auth.jdbc.security;

import java.security.KeyPair;

/**
 * @author ashwinrayaprolu
 *
 */
public class SystemContext {
	private static SystemContext systemContext = new SystemContext();
	private KeyPair keys = null;

	public static SystemContext getInstance() {
		return systemContext;
	}

	public KeyPair getKeys() {
		return keys;
	}

	public void setKeys(KeyPair keys) {
		this.keys = keys;
	}

}
