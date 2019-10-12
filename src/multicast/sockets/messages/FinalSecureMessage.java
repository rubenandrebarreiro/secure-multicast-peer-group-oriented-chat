package multicast.sockets.messages;

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

import java.net.DatagramPacket;

import multicast.common.CommonUtils;
import multicast.sockets.messages.components.FastSecureMessageCheck;
import multicast.sockets.messages.components.SecureMessageAttributes;
import multicast.sockets.messages.components.SecureMessageHeader;
import multicast.sockets.messages.components.SecureMessageMetaHeader;
import multicast.sockets.messages.components.SecureMessagePayload;

/**
 * 
 * Class for the Final Secure Message.
 * 
 * @supervisor Prof. Henrique Joao Domingos - hj@fct.unl.pt
 * 
 * @author Eduardo Bras Silva (no. 41798) - emf.silva@campus.fct.unl.pt
 * @author Ruben Andre Barreiro (no. 42648) - r.barreiro@campus.fct.unl.pt
 *
 */
public class FinalSecureMessage {
	
	// Global Instance Variables:
	/**
	 * The Secure Message's Meta-Header
	 */
	private SecureMessageMetaHeader secureMessageMetaHeader;
	
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
	 * The Fast Secure Message's Check
	 */
	private FastSecureMessageCheck fastSecureMessageCheck;
	
	/**
	 * The Final Secure Message serialized
	 */
	private byte[] finalSecureMessageSerialized;
	
	/**
	 * The boolean to keep the value to check if
	 * the Final Secure Message is serialized
	 */
	private boolean isFinalSecureMessageSerialized;
	
	
	
	// Constructors:
	/**
	 * TODO
	 * 
	 * @param datagramPacket
	 * 
	 * @param
	 */
	public FinalSecureMessage(DatagramPacket datagramPacket, boolean firstMessage) {
		
		// TODO confirmar
		this.secureMessagePayload = new SecureMessagePayload(datagramPacket.getSocketAddress().toString(), 0, 0, datagramPacket.getData());

		this.fastSecureMessageCheck = new FastSecureMessageCheck(this.secureMessagePayload.getSecureMessagePayloadSerialized());
		this.secureMessageAttributes = new SecureMessageAttributes(null, null, null, null, null, null, null);
		this.secureMessageHeader = new SecureMessageHeader((byte) 0, "aa", (byte) 0);
		this.fastSecureMessageCheck = new FastSecureMessageCheck(null);
		
		this.secureMessageMetaHeader = new SecureMessageMetaHeader(this.secureMessageHeader.getSecureMessageHeaderSerialized().length,
																					  this.secureMessageAttributes.getSecureMessageAttributesSerialized().length, 
																					  this.secureMessagePayload.getSecureMessagePayloadSerialized().length, 
																					  0);
	}
	
	/**
	 * Builds the several components of the Final Secure Message serialized.
	 */
	public void buildFinalSecureMessageSerialized() {
		
		if(!this.isFinalSecureMessageSerialized) {
			byte[] secureMessageMetaHeaderSerialized = 
					this.secureMessageMetaHeader.getSecureMessageMetaHeaderSerialized();
			
			byte[] secureMessageHeaderSerialized = 
					this.secureMessageHeader.getSecureMessageHeaderSerialized();
			
			byte[] secureMessageAttributesSerializedHashed = 
					this.secureMessageAttributes.getSecureMessageAttributesSerializedHashed();
			
			byte[] sizeOfSecureMessagePayloadSerialized = 
					CommonUtils.fromIntToByteArray(this.sizeOfSecureMessagePayload);
			
			byte[] secureMessagePayloadSerialized = 
					this.secureMessagePayload.getSecureMessagePayloadSerialized();
			
			byte[] fastSecureMessageCheckSerializedHashed =
					this.fastSecureMessageCheck.getSecureMessageSerializedHashed();
			
			
			// Operations to Fill a Byte Array, with the following parameters:
			// 1) src - The source of the array to be copied
			// 2) srcPos - The position from the array to be copied, representing the first element to be copied
			// 3) dest - The destination of the array to be copied
			// 4) destPos - The position of the array where will be placed the new copy,
			//              representing the first element where new data will be placed
			// 5) length - The length of the data to be copied from the source array to the destination array
			
			// The offset related to fulfillment of the serialization process
			int serializationOffset = 0;
			
			// Fills the byte array of the Final Secure Message with the Secure Message's Meta-Header,
			// From the position initial to the corresponding to the length of Secure Message's Meta-Header
			System.arraycopy(secureMessageMetaHeaderSerialized, 0,
							 this.finalSecureMessageSerialized, serializationOffset, secureMessageMetaHeaderSerialized.length);
			serializationOffset += secureMessageMetaHeaderSerialized.length;

			// Fills the byte array of the Final Secure Message with the Secure Message's Header,
			// From the position corresponding to the length of Secure Message's Meta-Header to
			// the corresponding to the length of Secure Message's Header
			System.arraycopy(secureMessageHeaderSerialized, 0,
							 this.finalSecureMessageSerialized, serializationOffset, secureMessageHeaderSerialized.length);
			serializationOffset += secureMessageHeaderSerialized.length;

			// Fills the byte array of the Final Secure Message with the Secure Message's Attributes,
			// From the position corresponding to the length of Secure Message's Header to
			// the corresponding to the length of Secure Message's Attributes
			System.arraycopy(secureMessageAttributesSerializedHashed, 0,
							 this.finalSecureMessageSerialized, serializationOffset, secureMessageAttributesSerializedHashed.length);
			serializationOffset += secureMessageAttributesSerializedHashed.length;

			// Fills the byte array of the Final Secure Message with the size of Secure Message's Payload,
			// From the position corresponding to the length of Secure Message's Attributes to
			// the corresponding to the length of size of Secure Message's Payload
			System.arraycopy(sizeOfSecureMessagePayloadSerialized, 0,
							 this.finalSecureMessageSerialized, serializationOffset, sizeOfSecureMessagePayloadSerialized.length);
			serializationOffset += sizeOfSecureMessagePayloadSerialized.length;
			
			// Fills the byte array of the Final Secure Message with the Secure Message's Payload,
			// From the position corresponding to the length of size of Secure Message's Payload to
			// the corresponding to the length of Secure Message's Payload
			System.arraycopy(secureMessagePayloadSerialized, 0,
							 this.finalSecureMessageSerialized, serializationOffset, secureMessagePayloadSerialized.length);
			serializationOffset += secureMessagePayloadSerialized.length;
			
			// Fills the byte array of the Final Secure Message with the Fast Secure Message's Check,
			// From the position corresponding to the length of Secure Message's Payload to
			// the corresponding to the length of Fast Secure Message's Check
			System.arraycopy(fastSecureMessageCheckSerializedHashed, 0,
							 this.finalSecureMessageSerialized, serializationOffset, fastSecureMessageCheckSerializedHashed.length);
			serializationOffset += fastSecureMessageCheckSerializedHashed.length;
			
			
			// The Final Secure Message have already its serialization done
			this.isFinalSecureMessageSerialized = true;
		}
	}
	
	/**
	 * Returns the final Secure Message serialized.
	 * 
	 * @return the final Secure Message serialized
	 */
	public byte[] getFinalSecureMessageSerialized() {
		return this.isFinalSecureMessageSerialized ? this.finalSecureMessageSerialized : null;
	}
}