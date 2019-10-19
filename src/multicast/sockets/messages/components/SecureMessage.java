package multicast.sockets.messages.components;

import java.net.DatagramPacket;
import java.util.Properties;

import multicast.common.CommonUtils;
import multicast.common.VersionNumber;

public class SecureMessage {
	
	// Global Instance Variables:
	/**
	 * The Secure Message's Header
	 */
	private SecureMessageHeader secureMessageHeader;
	
	/**
	 * The Secure Message's Attributes
	 */
	private SecureMessageAttributes secureMessageAttributes;
	
	/**
	 * The size of the Secure Message's Payload
	 */
	private int sizeOfSecureMessagePayload;
	
	/**
	 * The Secure Message's Payload
	 */
	private SecureMessagePayload secureMessagePayload;
	
	/**
	 * The Secure Message serialized
	 */
	private byte[] secureMessageSerialized;
	
	/**
	 * The boolean to keep the value to check if
	 * the Secure Message is serialized
	 */
	private boolean isSecureMessageSerialized;
	
	
	// Constructors:
	/**
	 * Constructor #1:
	 * - The Constructor of the Secure Message,
	 *   from the respectively basic components of it.
	 * 
	 * @param datagramPacket the Datagram Packet corresponding to the real content of the Message
	 * 
	 * @param sequenceNumber the Sequence Number of the Secure Message
	 * 
	 * @param randomNonce the Random Nonce of the Secure Message
	 * 
	 * @param properties the Properties of the Secure Message's Attributes
	 * 
	 * @param messageType the Message's Type of the Secure Message
	 */
	public SecureMessage(DatagramPacket datagramPacket, int sequenceNumber, int randomNonce, Properties properties, byte messageType) {
		
		
		this.secureMessageAttributes = new SecureMessageAttributes(properties.getProperty("sid"), /* TODO - Session's Name */ null,
																   properties.getProperty("sea"), properties.getProperty("seaks"), properties.getProperty("mode"),
																   properties.getProperty("inthash"), properties.getProperty("macks"));
		
		this.secureMessageHeader = new SecureMessageHeader(VersionNumber.VERSION_01.getVersionNumber(), properties.getProperty("sid"), messageType);
		
		this.secureMessagePayload = new SecureMessagePayload(/* TODO - fromPeerID */ null, sequenceNumber, randomNonce, datagramPacket.getData());
		
		this.isSecureMessageSerialized = false;
	}
	
	
	// Methods:
	/**
	 * Returns the Secure Message's Header.
	 * 
	 * @return the Secure Message's Header
	 */
	public SecureMessageHeader getSecureMessageHeader() {
		return this.secureMessageHeader;
	}
	
	/**
	 * Returns the Secure Message's Attributes.
	 * 
	 * @return the Secure Message's Attributes
	 */
	public SecureMessageAttributes getSecureMessageAttributes() {
		return this.secureMessageAttributes;
	}
	
	/**
	 * Returns the size of the Secure Message's Payload.
	 * 
	 * @return the size of the Secure Message's Payload
	 */
	public int getSizeOfSecureMessagePayload() {
		return this.sizeOfSecureMessagePayload;
	}
	
	/**
	 * Returns the Secure Message's Payload.
	 * 
	 * @return the Secure Message's Payload
	 */
	public SecureMessagePayload getSecureMessagePayload() {
		return this.secureMessagePayload;
	}
	
	/**
	 * Return the Secure Message serizalized.
	 * 
	 * @return the Secure Message serizalized
	 */
	public byte[] getSecureMessageSerialized() {
		return this.isSecureMessageSerialized ? this.secureMessageSerialized : null;
	}
	
	/**
	 * 
	 */
	public void buildSecureMessageSerialized() {
		if(!this.isSecureMessageSerialized) {			
			
			this.secureMessageHeader.buildMessageHeaderSerialized();
			byte[] secureMessageHeaderSerialized = 
					this.secureMessageHeader.getSecureMessageHeaderSerialized();
			
			this.secureMessageAttributes.buildSecureMessageAttributesSerialized();
			this.secureMessageAttributes.buildFinalSecureMessageAttributesSerializedHashed();
			byte[] secureMessageAttributesSerializedHashed = 
					this.secureMessageAttributes.getSecureMessageAttributesSerializedHashed();

			this.secureMessagePayload.buildIntegrityControlHashedSerialized();
			this.secureMessagePayload.buildSecureMessagePayloadSerialized();
			this.secureMessagePayload.buildSecureMessagePayloadSerializedSymmetricEncryptionCiphered();
			byte[] secureMessagePayloadSerialized = 
					this.secureMessagePayload.getSecureMessagePayloadSerialized();
			
			this.sizeOfSecureMessagePayload = this.secureMessagePayload.getSecureMessagePayloadSerialized().length;
			byte[] sizeOfSecureMessagePayloadSerialized = 
					CommonUtils.fromIntToByteArray(this.sizeOfSecureMessagePayload);
			
			
			// Operations to Fill a Byte Array, with the following parameters:
			// 1) src - The source of the array to be copied
			// 2) srcPos - The position from the array to be copied, representing the first element to be copied
			// 3) dest - The destination of the array to be copied
			// 4) destPos - The position of the array where will be placed the new copy,
			//              representing the first element where new data will be placed
			// 5) length - The length of the data to be copied from the source array to the destination array
			
			// The offset related to fulfillment of the serialization process
			int serializationOffset = 0;
			
			// Fills the byte array of the Secure Message with the Secure Message's Header,
			// From the initial position to the corresponding to the length of Secure Message's Header
			System.arraycopy(secureMessageHeaderSerialized, 0,
							 this.secureMessageSerialized, serializationOffset, secureMessageHeaderSerialized.length);
			serializationOffset += secureMessageHeaderSerialized.length;

			// Fills the byte array of the Secure Message with the Secure Message's Attributes,
			// From the position corresponding to the length of Secure Message's Header to
			// the corresponding to the length of Secure Message's Attributes
			System.arraycopy(secureMessageAttributesSerializedHashed, 0,
							 this.secureMessageSerialized, serializationOffset, secureMessageAttributesSerializedHashed.length);
			serializationOffset += secureMessageAttributesSerializedHashed.length;

			// Fills the byte array of the Final Secure Message with the size of Secure Message's Payload,
			// From the position corresponding to the length of Secure Message's Attributes to
			// the corresponding to the length of size of Secure Message's Payload
			System.arraycopy(sizeOfSecureMessagePayloadSerialized, 0,
							 this.secureMessageSerialized, serializationOffset, sizeOfSecureMessagePayloadSerialized.length);
			serializationOffset += sizeOfSecureMessagePayloadSerialized.length;
			
			// Fills the byte array of the Final Secure Message with the Secure Message's Payload,
			// From the position corresponding to the length of size of Secure Message's Payload to
			// the corresponding to the length of Secure Message's Payload
			System.arraycopy(secureMessagePayloadSerialized, 0,
							 this.secureMessageSerialized, serializationOffset, secureMessagePayloadSerialized.length);
			serializationOffset += secureMessagePayloadSerialized.length;
			
			
			// The Secure Message have already its serialization done
			this.isSecureMessageSerialized = true;
		}
	}
}