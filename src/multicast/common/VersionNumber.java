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

public enum VersionNumber {
	VERSION_00((byte) 0x00), VERSION_01((byte) 0x01);
	
	private byte versionNumber;
	
	/**
	 * 
	 * 
	 * @param versionNumber
	 */
	private VersionNumber(byte versionNumber) {
		this.versionNumber = versionNumber;
	}
	
	public byte getVersionNumber() {
		return this.versionNumber;
	}
}