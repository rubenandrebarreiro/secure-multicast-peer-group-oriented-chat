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
 * Enumeration for the Version's Number of the Secure Multicast Chat Protocol.
 * 
 * @supervisor Prof. Henrique Joao Domingos - hj@fct.unl.pt
 * 
 * @author Eduardo Bras Silva (no. 41798) - emf.silva@campus.fct.unl.pt
 * @author Ruben Andre Barreiro (no. 42648) - r.barreiro@campus.fct.unl.pt
 *
 */
public enum VersionNumber {
	
	// Enumerations:
	/**
	 * The several Enumerations for the Version's Numbers
	 */
	VERSION_01((byte) 0x01), VERSION_02((byte) 0x02),
	VERSION_03((byte) 0x03), VERSION_04((byte) 0x04);
	
	
	// Global Instance Variables:
	/**
	 * The Version's Number 
	 */
	private byte versionNumber;
	
	
	// Constructors:
	/**
	 * Constructor #1:
	 * - The Constructor for the Version's Number.
	 * 
	 * @param versionNumber the Version's Number
	 */
	private VersionNumber(byte versionNumber) {
		this.versionNumber = versionNumber;
	}
	
	
	// Methods/Functions:
	/**
	 * Returns the Version's Number.
	 * 
	 * @return the Version's Number
	 */
	public byte getVersionNumber() {
		return this.versionNumber;
	}
	
}