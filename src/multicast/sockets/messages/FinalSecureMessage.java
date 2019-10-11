package multicast.sockets.messages;

import java.net.DatagramPacket;

import multicast.sockets.messages.components.SecureMessageAttributes;
import multicast.sockets.messages.components.SecureMessageHeader;
import multicast.sockets.messages.components.SecureMessageMetaHeader;
import multicast.sockets.messages.components.SecureMessagePayload;

public class FinalSecureMessage {
	
	public FinalSecureMessage(DatagramPacket datagramPacket) {
		
		// TODO confirmar
		SecureMessagePayload secureMessagePayload = new SecureMessagePayload(datagramPacket.getSocketAddress().toString(), 0, 0, datagramPacket.getData());
		SecureMessageAttributes secureMessageAttributes = new SecureMessageAttributes(null, null, null, null, null, null, null);
		SecureMessageHeader secureMessageHeader = new SecureMessageHeader((byte) 0, "aa", (byte) 0);
		SecureMessageMetaHeader secureMessageMetaHeader = new SecureMessageMetaHeader(0, 0, 0, 0);
	}
}
