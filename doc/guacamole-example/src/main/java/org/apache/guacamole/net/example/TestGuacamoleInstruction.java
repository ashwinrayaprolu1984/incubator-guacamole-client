/**
 * 
 */
package org.apache.guacamole.net.example;

import org.apache.guacamole.net.GuacamoleTunnel;
import org.apache.guacamole.protocol.GuacamoleConfiguration;
import org.apache.guacamole.protocol.GuacamoleInstruction;

/**
 * @author ashwinrayaprolu
 *
 */
public class TestGuacamoleInstruction {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// guacd connection information
		String hostname = "swiftui";
		int port = 4822;

		// VNC connection information
		GuacamoleConfiguration config = new GuacamoleConfiguration();
		config.setProtocol("rdp");
		config.setParameter("hostname", "bigbrown.chrims.com");
		config.setParameter("username", "chrims.com\\arayaprolu");
		config.setParameter("password", "MySecret@123");
		config.setParameter("security", "tls");
		config.setParameter("ignore-cert", "true");

		System.out.println(new GuacamoleInstruction(
				GuacamoleTunnel.INTERNAL_DATA_OPCODE, "test").toString());

	}

}
