package multicast.sockets.messages;

import java.net.DatagramPacket;

import multicast.sockets.messages.components.FastSecureMessageCheck;
import multicast.sockets.messages.components.SecureMessageAttributes;
import multicast.sockets.messages.components.SecureMessageHeader;
import multicast.sockets.messages.components.SecureMessageMetaHeader;
import multicast.sockets.messages.components.SecureMessagePayload;

public class FinalSecureMessage {
	
	// Global Instance Variables:

	/**
	 * 
	 */
	private SecureMessageHeader secureMessageHeader;
	
	/**
	 * 
	 */
	private SecureMessageAttributes secureMessageAttributes;
	
	/**
	 * 
	 */
	private SecureMessagePayload secureMessagePayload;
	
	/**
	 * 
	 */
	private FastSecureMessageCheck fastSecureMessageCheck;
	
	// Constructors:
	
	/**
	 * TODO
	 * 
	 * @param datagramPacket
	 */
	public FinalSecureMessage(DatagramPacket datagramPacket) {
		
		// TODO confirmar
		this.secureMessagePayload = new SecureMessagePayload(datagramPacket.getSocketAddress().toString(), 0, 0, datagramPacket.getData());

		this.fastSecureMessageCheck = new FastSecureMessageCheck(this.secureMessagePayload.getSecureMessagePayloadSerialized());
		this.secureMessageAttributes = new SecureMessageAttributes(null, null, null, null, null, null, null);
		this.secureMessageHeader = new SecureMessageHeader((byte) 0, "aa", (byte) 0);
		
		
		SecureMessageMetaHeader secureMessageMetaHeader = new SecureMessageMetaHeader(this.secureMessageHeader.getSecureMessageHeaderSerialized().length,
																					  this.secureMessageAttributes.getSecureMessageAttributesSerialized().length, 
																					  this.secureMessagePayload.getSecureMessagePayloadSerialized().length, 
																					  0);
	}
}