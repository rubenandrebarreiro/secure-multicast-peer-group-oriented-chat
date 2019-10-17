package multicast.common;

/**
 * 
 * Secure Multicast Peer Group Oriented Chat - Phase #1
 * 
 * Network and Computer Systems Security
 * 
 * Faculty of Science and Technology of New University of Lisbon
 * (FCT NOVA | FCT/UNL)
 * 
 * Integrated Master of Computer Science and Engineering
 * (BSc. + MSc. Bologna Degree)
 * 
 * Academic Year 2019/2020
 * 
 */

public enum MessageType {
	JOIN((byte) 0x00), LEAVE((byte) 0x01), NORMAL_MESSAGE((byte) 0x02);
	
	private byte messageType;
	
	/**
	 * 
	 * 
	 * @param versionNumber
	 */
	private MessageType(byte messageType) {
		this.messageType = messageType;
	}
	
	public byte getMessageType() {
		return this.messageType;
	}
}