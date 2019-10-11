package multicast.sockets.messages.components;

public class FastSecureMessageCheck {
	
	// Global Instance Variables:
	
	/**
	 * 
	 */
	private byte[] secureMessagePayloadSerialized;
	
	public FastSecureMessageCheck(byte[] secureMessagePayloadSerialized) {
		this.secureMessagePayloadSerialized = secureMessagePayloadSerialized;
	}
	
	
	public byte[] getSecureMessagePayloadSerialized() {
		return this.secureMessagePayloadSerialized;
	}
}
