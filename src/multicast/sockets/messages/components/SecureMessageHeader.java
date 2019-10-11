package multicast.sockets.messages.components;

import multicast.common.CommonUtils;

public class SecureMessageHeader {
	
	private byte versionNumber;
	
	private String sessionID;
	
	private byte messageType;
	
	private byte[] secureMessageHeaderSerialized;
	
	private boolean isSecureMessageHeaderSerialized;
	
	public SecureMessageHeader(byte versionNumber, String sessionID, byte messageType) {
		this.versionNumber = versionNumber;
		this.sessionID = sessionID;
		this.messageType = messageType;
		
		this.isSecureMessageHeaderSerialized = false;
	}
	
	public SecureMessageHeader(byte[] secureMessageHeaderSerialized) {
		this.secureMessageHeaderSerialized = secureMessageHeaderSerialized;
		
		this.versionNumber = this.secureMessageHeaderSerialized[0];
		
		byte[] sessionIDSerialized = new byte[ (secureMessageHeaderSerialized.length - ( 2 * CommonUtils.BYTE_LENGTH ) ) ];
		
		System.arraycopy(secureMessageHeaderSerialized, CommonUtils.BYTE_LENGTH,
						 sessionIDSerialized, 0, ( secureMessageHeaderSerialized.length - CommonUtils.BYTE_LENGTH ));
		
		this.sessionID = CommonUtils.fromByteArrayToString(sessionIDSerialized);
		
		this.messageType = secureMessageHeaderSerialized[ ( secureMessageHeaderSerialized.length - CommonUtils.BYTE_LENGTH ) ];
	}

	public byte getVersionNumber() {
		return this.versionNumber;
	}
	 
	public String getSessionID() {
		return this.sessionID;
	}

	public byte getMessageType() {
		return this.messageType;
	}

	public void buildMessageHeaderSerialization() {
		if(!this.isSecureMessageHeaderSerialized) {
			
			byte versionNumberSerialized = versionNumber;
			byte[] sessionIDSerialized = CommonUtils.fromStringToByteArray(this.getSessionID());
			byte messageTypeSerialized = messageType;
			
			int sizeOfMessageHeaderSerialized = ( sessionIDSerialized.length + ( 2 * CommonUtils.BYTE_LENGTH ) );

			this.secureMessageHeaderSerialized = new byte[sizeOfMessageHeaderSerialized];
			
			int serializationOffset = 0;

			// Fills the byte array of the Secure Message Header with the serialization of the Version's Number,
			// From the position corresponding to the length of the byte of the Version's Number
			System.arraycopy(versionNumberSerialized, 0, this.secureMessageHeaderSerialized, 0, CommonUtils.BYTE_LENGTH);
			serializationOffset += CommonUtils.BYTE_LENGTH;
			
			// Fills the byte array of the Secure Message Header with the serialization of the Session's ID,
			// From the position corresponding to the length of the byte array of the Session's ID
			System.arraycopy(sessionIDSerialized, 0, this.secureMessageHeaderSerialized, serializationOffset, sessionIDSerialized.length);
			serializationOffset += sessionIDSerialized.length;
			
			// Fills the byte array of the Secure Message Header with the serialization of the Message's Type,
			// From the position corresponding to the length of the byte of the Message's Type
			System.arraycopy(messageTypeSerialized, 0, this.secureMessageHeaderSerialized, serializationOffset, CommonUtils.BYTE_LENGTH);
			serializationOffset += CommonUtils.BYTE_LENGTH;
			
			this.isSecureMessageHeaderSerialized = !this.isSecureMessageHeaderSerialized;
		}	
	}
	
	public byte[] getSecureMessageHeaderSerialized() {
		return this.isSecureMessageHeaderSerialized ? this.secureMessageHeaderSerialized : null;
	}
}