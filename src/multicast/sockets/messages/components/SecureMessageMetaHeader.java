package multicast.sockets.messages.components;

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

import multicast.common.CommonUtils;

/**
 * 
 * Class for the Secure Message's Meta-Header.
 * 
 * @supervisor Prof. Henrique Joao Domingos - hj@fct.unl.pt
 * 
 * @author Eduardo Bras Silva (no. 41798) - emf.silva@campus.fct.unl.pt
 * @author Ruben Andre Barreiro (no. 42648) - r.barreiro@campus.fct.unl.pt
 *
 */
public class SecureMessageMetaHeader {
	
	// Global Instance Variables:
	/**
	 * The size of the Secure Message's Header
	 */
	private int sizeOfSecureMessageHeader;
	
	/**
	 * The size of the Secure Message's Attributes
	 */
	private int sizeOfSecureMessageAttributes;
	
	/**
	 * The size of the Secure Message's Payload
	 */
	private int sizeOfSecureMessagePayload;
	
	/**
	 * The size of the String for From Peer ID
	 */
	private int sizeOfFromPeerID;
	
	/**
	 * The size of the Message
	 */
	private int sizeOfMessage;
	
	/**
	 * The size of the Integrity Control
	 */
	private int sizeOfIntegrityControl;
	
	
	/**
	 * The size of the Fast Secure Message's Check
	 */
	private int sizeOfFastSecureMessageCheck;
	
	/**
	 * The Secure Message's Meta-Header serialized
	 */
	private byte[] secureMessageMetaHeaderSerialized;

	/**
	 * The boolean to keep the value to check if
	 * the Secure Message's Meta-Header is serialized
	 */
	private boolean isSecureMessageMetaHeaderSerialized;
	
	/**
	 * The size of the Secure Message's Header serialized
	 */
	private byte[] sizeOfSecureMessageHeaderSerialized;
	
	/**
	 * The size of the Secure Message's Attributes hashed and serialized
	 */
	private byte[] sizeOfSecureMessageAttributesHashedSerialized;
	
	/**
	 * The size of the Secure Message's Payload serialized
	 */
	private byte[] sizeOfSecureMessagePayloadSerialized;
	
	private byte[] sizeOfFromPeerIDSerialized;
	
	private byte[] sizeOfMessageSerialized;
	
	private byte[] sizeOfIntegrityControlSerialized;
	
	
	/**
	 * The size of the Fast Secure Message's Check serialized
	 */
	private byte[] sizeOfFastSecureMessageCheckSerialized;
	
	
	
	// Constructors:
	/**
	 * Constructor #1:
	 * - The Constructor of the Secure Message's Meta-Header,
	 *   with the size of the respectively components of the Secure Message.
	 * 
	 * @param sizeOfSecureMessageHeader the size of the Secure Message's Header
	 * 
	 * @param sizeOfSecureMessageAttributes the size of the Secure Message's Attribute
	 * 
	 * @param sizeOfSecureMessagePayload the size of the Secure Message's Payload
	 * 
	 * @param sizeOfFastSecureMessageCheck the size of the Fast Secure Message's Check
	 */
	public SecureMessageMetaHeader(int sizeOfSecureMessageHeader,
			                       int sizeOfSecureMessageAttributes,
			                       int sizeOfSecureMessagePayload,
			                       int sizeOfFromPeerID,
			                       int sizeOfMessage,
			                       int sizeOfIntegrityControl,
			                       int sizeOfFastSecureMessageCheck) {
		
		this.sizeOfSecureMessageHeader = sizeOfSecureMessageHeader;
		this.sizeOfSecureMessageAttributes = sizeOfSecureMessageAttributes;
		this.sizeOfSecureMessagePayload = sizeOfSecureMessagePayload;
		this.sizeOfFromPeerID = sizeOfFromPeerID;
		this.sizeOfMessage = sizeOfMessage;
		this.sizeOfIntegrityControl = sizeOfIntegrityControl;
		
		this.isSecureMessageMetaHeaderSerialized = false;
	}
	
	/**
	 * Constructor #2:
	 * - The Constructor of the Secure Message's Meta-Header,
	 *   from the concatenation of the respectively serialized sizes of the components of the Secure Message.
	 * 
	 * @param secureMessageMetaHeaderSerialized the concatenation of the respectively serialized sizes of
	 *        the components of the Secure Message
	 */
	public SecureMessageMetaHeader(byte[] secureMessageMetaHeaderSerialized) {
		this.secureMessageMetaHeaderSerialized = secureMessageMetaHeaderSerialized;
		
		this.sizeOfSecureMessageHeaderSerialized = new byte[CommonUtils.INTEGER_IN_BYTES_LENGTH];
		this.sizeOfSecureMessageAttributesHashedSerialized = new byte[CommonUtils.INTEGER_IN_BYTES_LENGTH];
		this.sizeOfSecureMessagePayloadSerialized = new byte[CommonUtils.INTEGER_IN_BYTES_LENGTH];
		this.sizeOfFromPeerIDSerialized = new byte[CommonUtils.INTEGER_IN_BYTES_LENGTH];
		this.sizeOfMessageSerialized = new byte[CommonUtils.INTEGER_IN_BYTES_LENGTH];
		this.sizeOfIntegrityControlSerialized = new byte[CommonUtils.INTEGER_IN_BYTES_LENGTH];
		this.sizeOfFastSecureMessageCheckSerialized = new byte[CommonUtils.INTEGER_IN_BYTES_LENGTH];
	
		this.isSecureMessageMetaHeaderSerialized = true;
	}
	
	
	
	// Methods:
	/**
	 * Returns the size of the Secure Message's Header.
	 * 
	 * @return the size of the Secure Message's Header
	 */
	public int getSizeOfSecureMessageHeader() {
		return this.isSecureMessageMetaHeaderSerialized ? null : this.sizeOfSecureMessageHeader;
	}
	
	/**
	 * Returns the size of the Secure Message's Attributes.
	 * 
	 * @return the size of the Secure Message's Attributes
	 */
	public int getSizeOfSecureMessageAttributes() {
		return this.isSecureMessageMetaHeaderSerialized ? null : this.sizeOfSecureMessageAttributes;
	}
	
	/**
	 * Returns the size of the Secure Message's Payload.
	 * 
	 * @return the size of the Secure Message's Payload
	 */
	public int getSizeOfSecureMessagePayload() {
		return this.isSecureMessageMetaHeaderSerialized ? null : this.sizeOfSecureMessagePayload;
	}
	

	/**
	 * Returns the size of the From Peer ID of Secure Message's Payload.
	 * 
	 * @return the size of the From Peer ID Secure Message's Payload
	 */
	public int getSizeOfFromPeerID() {
		return this.isSecureMessageMetaHeaderSerialized ? null : this.sizeOfFromPeerID;
	}
	
	/**
	 * Returns the size of the Message of Secure Message's Payload.
	 * 
	 * @return the size of the Message of Secure Message's Payload
	 */
	public int getSizeOfMessage() {
		return this.isSecureMessageMetaHeaderSerialized ? null : this.sizeOfMessage;
	}

	/**
	 * Returns the size of the Message of Secure Message's Payload.
	 * 
	 * @return the size of the Message of Secure Message's Payload
	 */
	public int getSizeOfIntegrityControl() {
		return this.isSecureMessageMetaHeaderSerialized ? null : this.sizeOfIntegrityControl;
	}
	
	
	
	/**
	 * Returns the size of the Secure Message.
	 * 
	 * @return the size of the Secure Message
	 */
	public int getSizeOfSecureMessage() {
		return this.isSecureMessageMetaHeaderSerialized ? null 
				: (this.sizeOfSecureMessageHeader + this.sizeOfSecureMessageAttributes + CommonUtils.INTEGER_IN_BYTES_LENGTH + this.sizeOfSecureMessagePayload);
	}
	
	/**
	 * Returns the size of the Fast Secure Message's Check.
	 * 
	 * @return the size of the Fast Secure Message's Check
	 */
	public int getSizeOfFastSecureMessageCheck() {
		return this.isSecureMessageMetaHeaderSerialized ? null : this.sizeOfFastSecureMessageCheck;
	}

	/**
	 * Builds the Secure Message's Meta-Header serialized.
	 */
	public void buildMessageMetaHeaderSerialized() {
		
		// This process it's only made if the Secure Message's Meta-Header is not serialized
		if(!this.isSecureMessageMetaHeaderSerialized) {
			
			// The size of the Secure Message's Header serialized
			this.sizeOfSecureMessageHeaderSerialized = CommonUtils.fromIntToByteArray(sizeOfSecureMessageHeader);
			
			// The size of the Secure Message's Attributes serialized
			this.sizeOfSecureMessageAttributesHashedSerialized = CommonUtils.fromIntToByteArray(sizeOfSecureMessageAttributes);
			
			// The size of the Secure Message's Payload serialized
			this.sizeOfSecureMessagePayloadSerialized = CommonUtils.fromIntToByteArray(sizeOfSecureMessagePayload);
			
			// The size of the Fast Secure Message's Check serialized
			this.sizeOfFromPeerIDSerialized = CommonUtils.fromIntToByteArray(sizeOfFromPeerID);
			
			// The size of the Fast Secure Message's Check serialized
			this.sizeOfMessageSerialized = CommonUtils.fromIntToByteArray(sizeOfMessage);
			
			// The size of the Fast Secure Message's Check serialized
			this.sizeOfIntegrityControlSerialized = CommonUtils.fromIntToByteArray(sizeOfIntegrityControl);
			
			// The size of the Fast Secure Message's Check serialized
			this.sizeOfFastSecureMessageCheckSerialized = CommonUtils.fromIntToByteArray(sizeOfFastSecureMessageCheck);
			
			
			// The size of the Secure Message's Meta-Header serialized
			int sizeOfSecureMessageMetaHeaderSerialized = ( ( CommonUtils.NUM_COMPONENTS_META_HEADER * CommonUtils.INTEGER_IN_BYTES_LENGTH ) + 
									                        ( CommonUtils.META_HEADER_OUTSIDE_SEPARATORS * CommonUtils.META_HEADER_OUTSIDE_SEPARATORS_LENGTH ) + 
									                        ( CommonUtils.META_HEADER_INSIDE_SEPARATORS * CommonUtils.META_HEADER_INSIDE_SEPARATORS_LENGTH ) );
			
			// The creation of the Secure Message's Meta-Header serialized
			this.secureMessageMetaHeaderSerialized = new byte[ sizeOfSecureMessageMetaHeaderSerialized ];
						
			// The separators of the Secure Message's Meta-Header serialized
			byte[] outsideSeparator = new byte[] {0x00, 0x00};
			byte[] insideSeparator = new byte[] {0x00};
			
			
			// Operations to Fill a Byte Array, with the following parameters:
			// 1) src - The source of the array to be copied
			// 2) srcPos - The position from the array to be copied, representing the first element to be copied
			// 3) dest - The destination of the array to be copied
			// 4) destPos - The position of the array where will be placed the new copy,
			//              representing the first element where new data will be placed
			// 5) length - The length of the data to be copied from the source array to the destination array
			
			// The offset related to fulfillment of the serialization process
			int serializationOffset = 0;
			
			// Fills the byte array of the Secure Message Meta-Header with an outside separator,
			// From the position corresponding to the length of 2 (outside separator)			
			System.arraycopy(outsideSeparator, 0, this.secureMessageMetaHeaderSerialized, serializationOffset, CommonUtils.META_HEADER_OUTSIDE_SEPARATORS_LENGTH);
			serializationOffset += CommonUtils.META_HEADER_OUTSIDE_SEPARATORS_LENGTH;
						
			// Fills the byte array of the Secure Message Meta-Header with the serialization of
			// The size of the Secure Message Header, from the position corresponding to the length of
			// The byte array of the size of the Secure Message Header
			System.arraycopy(this.sizeOfSecureMessageHeaderSerialized, 0, this.secureMessageMetaHeaderSerialized,
					         serializationOffset, this.sizeOfSecureMessageHeaderSerialized.length);
			serializationOffset += CommonUtils.INTEGER_IN_BYTES_LENGTH;
						
			// Fills the byte array of the Secure Message Meta-Header with an outside separator,
			// From the position corresponding to the length of 1 (inside separator)
			System.arraycopy(insideSeparator, 0, this.secureMessageMetaHeaderSerialized, serializationOffset, CommonUtils.META_HEADER_INSIDE_SEPARATORS_LENGTH);
			serializationOffset += CommonUtils.META_HEADER_INSIDE_SEPARATORS_LENGTH;
			
			// Fills the byte array of the Secure Message Meta-Header with the serialization of
			// The size of the Secure Message Attributes, from the position corresponding to the length of
			// The byte array of the size of the Secure Message Attributes
			System.arraycopy(this.sizeOfSecureMessageAttributesHashedSerialized, 0, this.secureMessageMetaHeaderSerialized,
			         		 serializationOffset, this.sizeOfSecureMessageAttributesHashedSerialized.length);
			serializationOffset += CommonUtils.INTEGER_IN_BYTES_LENGTH;
			
			// Fills the byte array of the Secure Message Meta-Header with an outside separator,
			// From the position corresponding to the length of 1 (inside separator)		
			System.arraycopy(insideSeparator, 0, this.secureMessageMetaHeaderSerialized, serializationOffset, CommonUtils.META_HEADER_INSIDE_SEPARATORS_LENGTH);
			serializationOffset += CommonUtils.META_HEADER_INSIDE_SEPARATORS_LENGTH;
			
			// Fills the byte array of the Secure Message Meta-Header with the serialization of
			// The size of the Secure Message Payload, from the position corresponding to the length of
			// The byte array of the size of the Secure Message Payload
			System.arraycopy(this.sizeOfSecureMessagePayloadSerialized, 0, this.secureMessageMetaHeaderSerialized,
	        				 serializationOffset, this.sizeOfSecureMessagePayloadSerialized.length);
			serializationOffset += CommonUtils.INTEGER_IN_BYTES_LENGTH;
			
			// Fills the byte array of the Secure Message Meta-Header with an outside separator,
			// From the position corresponding to the length of 1 (inside separator)
			System.arraycopy(insideSeparator, 0, this.secureMessageMetaHeaderSerialized, serializationOffset, CommonUtils.META_HEADER_INSIDE_SEPARATORS_LENGTH);
			serializationOffset += CommonUtils.META_HEADER_INSIDE_SEPARATORS_LENGTH;
			
			// Fills the byte array of the Secure Message Meta-Header with the serialization of
			// The size of the Secure Message Payload, from the position corresponding to the length of
			// The byte array of the size of the Secure Message Payload
			System.arraycopy(this.sizeOfFromPeerIDSerialized, 0, this.secureMessageMetaHeaderSerialized,
	        				 serializationOffset, this.sizeOfFromPeerIDSerialized.length);
			serializationOffset += CommonUtils.INTEGER_IN_BYTES_LENGTH;
			
			// Fills the byte array of the Secure Message Meta-Header with an outside separator,
			// From the position corresponding to the length of 1 (inside separator)
			System.arraycopy(insideSeparator, 0, this.secureMessageMetaHeaderSerialized, serializationOffset, CommonUtils.META_HEADER_INSIDE_SEPARATORS_LENGTH);
			serializationOffset += CommonUtils.META_HEADER_INSIDE_SEPARATORS_LENGTH;
			
			// Fills the byte array of the Secure Message Meta-Header with the serialization of
			// The size of the Secure Message Payload, from the position corresponding to the length of
			// The byte array of the size of the Secure Message Payload
			System.arraycopy(this.sizeOfMessageSerialized, 0, this.secureMessageMetaHeaderSerialized,
	        				 serializationOffset, this.sizeOfMessageSerialized.length);
			serializationOffset += CommonUtils.INTEGER_IN_BYTES_LENGTH;
			
			// Fills the byte array of the Secure Message Meta-Header with an outside separator,
			// From the position corresponding to the length of 1 (inside separator)
			System.arraycopy(insideSeparator, 0, this.secureMessageMetaHeaderSerialized, serializationOffset, CommonUtils.META_HEADER_INSIDE_SEPARATORS_LENGTH);
			serializationOffset += CommonUtils.META_HEADER_INSIDE_SEPARATORS_LENGTH;
			
			// Fills the byte array of the Secure Message Meta-Header with the serialization of
			// The size of the Secure Message Payload, from the position corresponding to the length of
			// The byte array of the size of the Secure Message Payload
			System.arraycopy(this.sizeOfIntegrityControlSerialized, 0, this.secureMessageMetaHeaderSerialized,
	        				 serializationOffset, this.sizeOfIntegrityControlSerialized.length);
			serializationOffset += CommonUtils.INTEGER_IN_BYTES_LENGTH;
			
			// Fills the byte array of the Secure Message Meta-Header with the serialization of
			// The size of the Fast Secure Message Check, from the position corresponding to the length of
			// The byte array of the size of the Fast Secure Message Check		
			System.arraycopy(this.sizeOfFastSecureMessageCheckSerialized, 0, this.secureMessageMetaHeaderSerialized,
	        				 serializationOffset, this.sizeOfFastSecureMessageCheckSerialized.length);
			serializationOffset += CommonUtils.INTEGER_IN_BYTES_LENGTH;
			
			// Fills the byte array of the Secure Message Meta-Header with an outside separator,
			// From the position corresponding to the length of 2 (outside separator)
			System.arraycopy(outsideSeparator, 0, this.secureMessageMetaHeaderSerialized, serializationOffset, CommonUtils.META_HEADER_OUTSIDE_SEPARATORS_LENGTH);
			serializationOffset += CommonUtils.META_HEADER_OUTSIDE_SEPARATORS_LENGTH;
			
			// The Secure Message's Meta-Header have already its serialization done
			this.isSecureMessageMetaHeaderSerialized = true;
		}
	}
	
	/**
	 * Builds the sizes of the several parts of the Secure Message from
	 * the Secure Message's Meta-Header serialized.
	 */
	public void buildSizesOfSecureMessageComponents() {
		
		// This process it's only made if the Secure Message's Meta-Header is serialized
		if(this.isSecureMessageMetaHeaderSerialized) {
			
			// The offset related to fulfillment of the Secure Message's Parts from the inverse process of serialization
			int offsetSecureMessageMetaHeaderSerializedParts = 0;
			
			// Fills the byte array of the size of the Secure Message's Header from
			// the byte array of the Secure Message Meta-Header serialized 
			offsetSecureMessageMetaHeaderSerializedParts += CommonUtils.META_HEADER_OUTSIDE_SEPARATORS_LENGTH;
			System.arraycopy(this.secureMessageMetaHeaderSerialized, offsetSecureMessageMetaHeaderSerializedParts,
							 this.sizeOfSecureMessageHeaderSerialized, 0, CommonUtils.INTEGER_IN_BYTES_LENGTH);
			offsetSecureMessageMetaHeaderSerializedParts += CommonUtils.INTEGER_IN_BYTES_LENGTH;

			// Fills the byte array of the size of the Secure Message's Attributes from
			// the byte array of the Secure Message Meta-Header serialized
			offsetSecureMessageMetaHeaderSerializedParts += CommonUtils.META_HEADER_INSIDE_SEPARATORS_LENGTH;
			System.arraycopy(this.secureMessageMetaHeaderSerialized, offsetSecureMessageMetaHeaderSerializedParts,
					 		 this.sizeOfSecureMessageAttributesHashedSerialized, 0, CommonUtils.INTEGER_IN_BYTES_LENGTH);
			offsetSecureMessageMetaHeaderSerializedParts += CommonUtils.INTEGER_IN_BYTES_LENGTH;

			// Fills the byte array of the size of the Secure Message's Payload from
			// the byte array of the Secure Message Meta-Header serialized
			offsetSecureMessageMetaHeaderSerializedParts += CommonUtils.META_HEADER_INSIDE_SEPARATORS_LENGTH;
			System.arraycopy(this.secureMessageMetaHeaderSerialized, offsetSecureMessageMetaHeaderSerializedParts,
					 		 this.sizeOfSecureMessagePayloadSerialized, 0, CommonUtils.INTEGER_IN_BYTES_LENGTH);
			offsetSecureMessageMetaHeaderSerializedParts += CommonUtils.INTEGER_IN_BYTES_LENGTH;

			// Fills the byte array of the size of the Secure Message's Payload from
			// the byte array of the Secure Message Meta-Header serialized
			offsetSecureMessageMetaHeaderSerializedParts += CommonUtils.META_HEADER_INSIDE_SEPARATORS_LENGTH;
			System.arraycopy(this.secureMessageMetaHeaderSerialized, offsetSecureMessageMetaHeaderSerializedParts,
					 		 this.sizeOfFromPeerIDSerialized, 0, CommonUtils.INTEGER_IN_BYTES_LENGTH);
			offsetSecureMessageMetaHeaderSerializedParts += CommonUtils.INTEGER_IN_BYTES_LENGTH;

			// Fills the byte array of the size of the Secure Message's Payload from
			// the byte array of the Secure Message Meta-Header serialized
			offsetSecureMessageMetaHeaderSerializedParts += CommonUtils.META_HEADER_INSIDE_SEPARATORS_LENGTH;
			System.arraycopy(this.secureMessageMetaHeaderSerialized, offsetSecureMessageMetaHeaderSerializedParts,
					 		 this.sizeOfMessageSerialized, 0, CommonUtils.INTEGER_IN_BYTES_LENGTH);
			offsetSecureMessageMetaHeaderSerializedParts += CommonUtils.INTEGER_IN_BYTES_LENGTH;

			// Fills the byte array of the size of the Secure Message's Payload from
			// the byte array of the Secure Message Meta-Header serialized
			offsetSecureMessageMetaHeaderSerializedParts += CommonUtils.META_HEADER_INSIDE_SEPARATORS_LENGTH;
			System.arraycopy(this.secureMessageMetaHeaderSerialized, offsetSecureMessageMetaHeaderSerializedParts,
					 		 this.sizeOfIntegrityControlSerialized, 0, CommonUtils.INTEGER_IN_BYTES_LENGTH);
			offsetSecureMessageMetaHeaderSerializedParts += CommonUtils.INTEGER_IN_BYTES_LENGTH;
			
			// Fills the byte array of the size of the Fast Secure Message's Check from
			// the byte array of the Secure Message Meta-Header serialized
			offsetSecureMessageMetaHeaderSerializedParts += CommonUtils.META_HEADER_INSIDE_SEPARATORS_LENGTH;
			System.arraycopy(this.secureMessageMetaHeaderSerialized, offsetSecureMessageMetaHeaderSerializedParts,
					 		 this.sizeOfFastSecureMessageCheckSerialized, 0, CommonUtils.INTEGER_IN_BYTES_LENGTH);

			
			// Inverse process of serialization of the several parts of the Secure Message's Parts
			this.sizeOfSecureMessageHeader = CommonUtils.fromByteArrayToInt(sizeOfSecureMessageHeaderSerialized);
			this.sizeOfSecureMessageAttributes = CommonUtils.fromByteArrayToInt(sizeOfSecureMessageAttributesHashedSerialized);
			this.sizeOfSecureMessagePayload = CommonUtils.fromByteArrayToInt(sizeOfSecureMessagePayloadSerialized);
			this.sizeOfFromPeerID = CommonUtils.fromByteArrayToInt(sizeOfFromPeerIDSerialized);
			this.sizeOfMessage = CommonUtils.fromByteArrayToInt(sizeOfMessageSerialized);
			this.sizeOfIntegrityControl = CommonUtils.fromByteArrayToInt(sizeOfIntegrityControlSerialized);
			this.sizeOfFastSecureMessageCheck = CommonUtils.fromByteArrayToInt(sizeOfFastSecureMessageCheckSerialized);
			
			// The Secure Message's Meta-Header have already its serialization undone
			this.isSecureMessageMetaHeaderSerialized = false;
		}
	}
	
	/**
	 * Returns the Secure Message's Meta-Header serialized.
	 * 
	 * @return the Secure Message's Meta-Header serialized
	 */
	public byte[] getSecureMessageMetaHeaderSerialized() {
		return this.isSecureMessageMetaHeaderSerialized ? this.secureMessageMetaHeaderSerialized : null;
	}
}