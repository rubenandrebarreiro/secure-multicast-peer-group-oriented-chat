package multicast.sockets.messages.components;

import multicast.common.CommonUtils;

public class SecureMessagePayload {
	
	private String fromPeerID;
	
	private int sequenceNumber;
	
	private int randomNonce;
	
	private byte[] messageSerialized;
	
	private byte[] integrityControlHashSerialiazed;
	
	private byte[] secureMessagePayloadSerialized;
	
	private boolean isSecureMessagePayloadSerialized;
	
	
	public SecureMessagePayload(String fromPeerID, int sequenceNumber, int randomNonce,
								byte[] messageSerialized, byte[] integrityControlSerialiazedHashed) {
		
		this.fromPeerID = fromPeerID;
		this.sequenceNumber = sequenceNumber;
		this.randomNonce = randomNonce;
		this.messageSerialized = messageSerialized;
		this.integrityControlHashSerialiazed = integrityControlSerialiazedHashed;
	
		this.isSecureMessagePayloadSerialized = false;
	}
	
	public String getFromPeerID() {
		return this.fromPeerID;
	}
	
	public int getSequenceNumber() {
		return this.sequenceNumber;
	}
	
	public int getRandomNonce() {
		return this.randomNonce;
	}
	
	public byte[] getMessageSerialized() {
		return this.messageSerialized;
	}
	
	public byte[] getIntegrityControlSerialiazedHashed() {
		return this.integrityControlHashSerialiazed;
	}
	
	public void buildSecureMessagePayloadSerialization() {
		if(!this.isSecureMessagePayloadSerialized) {
			
			byte[] fromPeerIDSerialized = this.fromPeerID.getBytes();
			
			byte[] sequenceNumberSerialized = CommonUtils.fromIntToByteArray(sequenceNumber);
			
			byte[] randomNonceSerialized = CommonUtils.fromIntToByteArray(randomNonce);
			
			int sizeOfSecureMessagePayloadSerialized = ( fromPeerIDSerialized.length + sequenceNumberSerialized.length + randomNonceSerialized.length + 
														 this.messageSerialized.length + this.integrityControlHashSerialiazed.length );

			this.secureMessagePayloadSerialized = new byte[sizeOfSecureMessagePayloadSerialized];
					
			int serializationOffset = 0;
			
			// Fills the byte array of the Secure Message Payload with the serialization of the From Peer's ID,
			// From the position corresponding to the length of the byte array of the From Peer's ID			
			System.arraycopy(fromPeerIDSerialized, 0, this.secureMessagePayloadSerialized, 0, fromPeerIDSerialized.length);
			serializationOffset += fromPeerIDSerialized.length;
			
			// Fills the byte array of the Secure Message Payload with the serialization of the Sequence Number,
			// From the position corresponding to the length of the byte array of the Sequence Number
			System.arraycopy(sequenceNumberSerialized, 0, this.secureMessagePayloadSerialized, serializationOffset, sequenceNumberSerialized.length);
			serializationOffset += sequenceNumberSerialized.length;
			
			// Fills the byte array of the Secure Message Payload with the serialization of the Random Nonce,
			// From the position corresponding to the length of the byte array of the Random Nonce
			System.arraycopy(randomNonceSerialized, 0, this.secureMessagePayloadSerialized, serializationOffset, randomNonceSerialized.length);
			serializationOffset += randomNonceSerialized.length;
			
			// Fills the byte array of the Secure Message Payload with the serialization of the Message,
			// From the position corresponding to the length of the byte array of the Message
			System.arraycopy(this.messageSerialized, 0, this.secureMessagePayloadSerialized, serializationOffset, this.messageSerialized.length);
			serializationOffset += this.messageSerialized.length;
			
			// Fills the byte array of the Secure Message Payload with the serialization of the Integrity Control Hash,
			// From the position corresponding to the length of the hashed byte array of the Integrity Control Hash
			System.arraycopy(this.integrityControlHashSerialiazed, 0, this.secureMessagePayloadSerialized, serializationOffset, this.integrityControlHashSerialiazed.length);
			serializationOffset += this.integrityControlHashSerialiazed.length;

			this.isSecureMessagePayloadSerialized = true;
		}
	}
	
	public byte[] getSecureMessagePayloadSerialized() {
		return this.isSecureMessagePayloadSerialized ? this.secureMessagePayloadSerialized : null;
	}
}