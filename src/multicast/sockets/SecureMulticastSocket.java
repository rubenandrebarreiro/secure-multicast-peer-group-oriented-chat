package multicast.sockets;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.MulticastSocket;
import java.util.LinkedHashMap;
import java.util.Map;

public class SecureMulticastSocket extends MulticastSocket {
	
	private int nonce;
	
	private Map<Integer, Long> nonces;
	
	public SecureMulticastSocket(int port) throws IOException {
		super(port);
		
		nonces = new LinkedHashMap<>();
	}
	
	@Override
	public void send(DatagramPacket datagramPacket) {
		try {
			super.send(this.buildFinalSecureMessage(datagramPacket));
		}
		catch (IOException inputOutputException) {
			System.err.println("Error occurred during the sending process of the Final Secure Message:");
			System.err.println("- Input/Output error occurred!!!");
			inputOutputException.printStackTrace();
		}
	}
	
	private DatagramPacket buildFinalSecureMessage(DatagramPacket datagramPacket) {
		
		return null;	
	}
	
	
}
