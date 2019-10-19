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

/**
 * 
 * Enumeration for the Message's Types of the Secure Multicast Chat Protocol.
 * 
 * @supervisor Prof. Henrique Joao Domingos - hj@fct.unl.pt
 * 
 * @author Eduardo Bras Silva (no. 41798) - emf.silva@campus.fct.unl.pt
 * @author Ruben Andre Barreiro (no. 42648) - r.barreiro@campus.fct.unl.pt
 *
 */
public enum MessageType {
	
	// Enumerations:
	/**
	 * The several Enumerations for the Message's Types
	 */
	MESSAGE_TYPE_1((byte) 0x01), MESSAGE_TYPE_2((byte) 0x02),
	MESSAGE_TYPE_3((byte) 0x03), MESSAGE_TYPE_4((byte) 0x04);
	
	
	// Global Instance Variables:
	/**
	 * The Message's Type
	 */
	private byte messageType;
	
	
	// Constructors:
	/**
	 * Constructor #1:
	 * - The Constructor for the Message's Type.
	 * 
	 * @param messageType the Message's Type
	 */
	private MessageType(byte messageType) {
		this.messageType = messageType;
	}
	
	
	// Methods/Functions:
	/**
	 * Returns the Message's Type.
	 * 
	 * @return the Message's Type
	 */
	public byte getMessageType() {
		return this.messageType;
	}
	
}