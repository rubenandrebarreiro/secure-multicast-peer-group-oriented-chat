package multicast.sockets.messages.components;

import multicast.common.CommonUtils;

public class SecureMessageMetaHeader {
	private int sizeOfSecureMessageHeader;
	private int sizeOfSecureMessageAttributes;
	private int sizeOfSecureMessagePayload;
	private int sizeOfFastSecureMessageCheck;
	
	private byte[] sizeOfSecureMessageHeaderSerialized;
	private byte[] sizeOfSecureMessageAttributesSerialized;
	private byte[] sizeOfSecureMessagePayloadSerialized;
	private byte[] sizeOfFastSecureMessageCheckSerialized;
	
	private byte[] secureMessageMetaHeaderSerialized;
	
	private boolean isSecureMessageMetaHeaderSerialized;
	
	public SecureMessageMetaHeader(int sizeOfSecureMessageHeader,
			                       int sizeOfSecureMessageAttributes,
			                       int sizeOfSecureMessagePayload,
			                       int sizeOfFastSecureMessageCheck) {
		
		this.sizeOfSecureMessageHeader = sizeOfSecureMessageHeader;
		this.sizeOfSecureMessageAttributes = sizeOfSecureMessageAttributes;
		this.sizeOfSecureMessagePayload = sizeOfSecureMessagePayload;
		this.sizeOfFastSecureMessageCheck = sizeOfFastSecureMessageCheck;
	}
	
	public SecureMessageMetaHeader(byte[] secureMessageMetaHeaderSerialized) {
		this.secureMessageMetaHeaderSerialized = secureMessageMetaHeaderSerialized;
		
		this.sizeOfSecureMessageHeaderSerialized = new byte[CommonUtils.INTEGER_LENGTH];
		this.sizeOfSecureMessageAttributesSerialized = new byte[CommonUtils.INTEGER_LENGTH];
		this.sizeOfSecureMessagePayloadSerialized = new byte[CommonUtils.INTEGER_LENGTH];
		this.sizeOfFastSecureMessageCheckSerialized = new byte[CommonUtils.INTEGER_LENGTH];
		
		
		int offsetSecureMessageHeaderSerializedParts = 0;
		
		System.arraycopy(this.secureMessageMetaHeaderSerialized, offsetSecureMessageHeaderSerializedParts,
						 this.sizeOfSecureMessageHeaderSerialized, 0, CommonUtils.INTEGER_LENGTH);
		offsetSecureMessageHeaderSerializedParts += CommonUtils.INTEGER_LENGTH;
		
		System.arraycopy(this.secureMessageMetaHeaderSerialized, offsetSecureMessageHeaderSerializedParts,
				 		 this.sizeOfSecureMessageAttributesSerialized, 0, CommonUtils.INTEGER_LENGTH);
		offsetSecureMessageHeaderSerializedParts += CommonUtils.INTEGER_LENGTH;
		
		System.arraycopy(this.secureMessageMetaHeaderSerialized, offsetSecureMessageHeaderSerializedParts,
				 		 this.sizeOfSecureMessagePayloadSerialized, 0, CommonUtils.INTEGER_LENGTH);
		offsetSecureMessageHeaderSerializedParts += CommonUtils.INTEGER_LENGTH;
		
		System.arraycopy(this.secureMessageMetaHeaderSerialized, offsetSecureMessageHeaderSerializedParts,
				 		 this.sizeOfFastSecureMessageCheckSerialized, 0, CommonUtils.INTEGER_LENGTH);
		
		
		this.sizeOfSecureMessageHeader = CommonUtils.fromByteArrayToInt(sizeOfSecureMessageHeaderSerialized);
		this.sizeOfSecureMessageAttributes = CommonUtils.fromByteArrayToInt(sizeOfSecureMessageAttributesSerialized);
		this.sizeOfSecureMessagePayload = CommonUtils.fromByteArrayToInt(sizeOfSecureMessagePayloadSerialized);
		this.sizeOfFastSecureMessageCheck = CommonUtils.fromByteArrayToInt(sizeOfFastSecureMessageCheckSerialized);
	}
	
	public int getSizeOfSecureMessageHeader() {
		return this.sizeOfSecureMessageHeader;
	}
	
	public int getSizeOfSecureMessageAttributes() {
		return this.sizeOfSecureMessageAttributes;
	}
	
	public int getSizeOfSecureMessagePayload() {
		return this.sizeOfSecureMessagePayload;
	}
	
	public int getSizeOfFastSecureMessageCheck() {
		return this.sizeOfFastSecureMessageCheck;
	}

	public void buildMessageMetaHeaderSerialization() {
		if(!this.isSecureMessageMetaHeaderSerialized) {
			
			this.sizeOfSecureMessageHeaderSerialized = CommonUtils.fromIntToByteArray(sizeOfSecureMessageHeader);
			this.sizeOfSecureMessageAttributesSerialized = CommonUtils.fromIntToByteArray(sizeOfSecureMessageAttributes);
			this.sizeOfSecureMessagePayloadSerialized = CommonUtils.fromIntToByteArray(sizeOfSecureMessagePayload);
			this.sizeOfFastSecureMessageCheckSerialized = CommonUtils.fromIntToByteArray(sizeOfFastSecureMessageCheck);
			
			int sizeOfSecureMessagePayloadSerialized = ( ( CommonUtils.NUM_COMPONENTS_META_HEADER * CommonUtils.INTEGER_LENGTH ) + 
									                     ( CommonUtils.META_HEADER_OUTSIDE_SEPARATORS * CommonUtils.META_HEADER_OUTSIDE_SEPARATORS_LENGTH ) + 
									                     ( CommonUtils.META_HEADER_INSIDE_SEPARATORS * CommonUtils.META_HEADER_INSIDE_SEPARATORS_LENGTH ) );
			
			this.secureMessageMetaHeaderSerialized = new byte[ sizeOfSecureMessagePayloadSerialized ];
		
			int serializationOffset = 0;
			
			byte[] outsideSeparator = new byte[] {0x00, 0x00};
			byte insideSeparator = 0x00;
			
			// Operations to Fill a Byte Array, with the following parameters:
			// 1) src - The source of the array to be copied
			// 2) srcPos - The position from the array to be copied, representing the first element to be copied
			// 3) dest - The destination of the array to be copied
			// 4) destPos - The position of the array where will be placed the new copy,
			//              representing the first element where new data will be placed
			// 5) length - The length of the data to be copied from the source array to the destination array
			
			
			// Fills the byte array of the Secure Message Meta Header with an outside separator,
			// From the position corresponding to the length of 2 (outside separator)			
			System.arraycopy(outsideSeparator, 0, this.secureMessageMetaHeaderSerialized, serializationOffset, CommonUtils.META_HEADER_OUTSIDE_SEPARATORS_LENGTH);
			serializationOffset += CommonUtils.META_HEADER_OUTSIDE_SEPARATORS_LENGTH;
			
			// Fills the byte array of the Secure Message Meta Header with the serialization of
			// The size of the Secure Message Header, from the position corresponding to the length of
			// The byte array of the size of the Secure Message Header
			System.arraycopy(this.sizeOfSecureMessageHeaderSerialized, 0, this.secureMessageMetaHeaderSerialized,
					         serializationOffset, this.sizeOfSecureMessageHeaderSerialized.length);
			serializationOffset += CommonUtils.INTEGER_LENGTH;
			
			// Fills the byte array of the Secure Message Meta Header with an outside separator,
			// From the position corresponding to the length of 1 (inside separator)
			System.arraycopy(insideSeparator, 0, this.secureMessageMetaHeaderSerialized, serializationOffset, CommonUtils.META_HEADER_INSIDE_SEPARATORS_LENGTH);
			serializationOffset += CommonUtils.META_HEADER_INSIDE_SEPARATORS_LENGTH;
			
			// Fills the byte array of the Secure Message Meta Header with the serialization of
			// The size of the Secure Message Attributes, from the position corresponding to the length of
			// The byte array of the size of the Secure Message Attributes
			System.arraycopy(this.sizeOfSecureMessageHeaderSerialized, 0, this.secureMessageMetaHeaderSerialized,
			         		 serializationOffset, this.sizeOfSecureMessageAttributesSerialized.length);
			serializationOffset += CommonUtils.INTEGER_LENGTH;
			
			// Fills the byte array of the Secure Message Meta Header with an outside separator,
			// From the position corresponding to the length of 1 (inside separator)		
			System.arraycopy(insideSeparator, 0, this.secureMessageMetaHeaderSerialized, serializationOffset, CommonUtils.META_HEADER_INSIDE_SEPARATORS_LENGTH);
			serializationOffset += CommonUtils.META_HEADER_INSIDE_SEPARATORS_LENGTH;
			
			// Fills the byte array of the Secure Message Meta Header with the serialization of
			// The size of the Secure Message Payload, from the position corresponding to the length of
			// The byte array of the size of the Secure Message Payload
			System.arraycopy(this.sizeOfSecureMessageHeaderSerialized, 0, this.secureMessageMetaHeaderSerialized,
	        				 serializationOffset, this.sizeOfSecureMessagePayloadSerialized.length);
			serializationOffset += CommonUtils.INTEGER_LENGTH;
			
			// Fills the byte array of the Secure Message Meta Header with an outside separator,
			// From the position corresponding to the length of 1 (inside separator)
			System.arraycopy(insideSeparator, 0, this.secureMessageMetaHeaderSerialized, serializationOffset, CommonUtils.META_HEADER_INSIDE_SEPARATORS_LENGTH);
			serializationOffset += CommonUtils.META_HEADER_INSIDE_SEPARATORS_LENGTH;
			
			// Fills the byte array of the Secure Message Meta Header with the serialization of
			// The size of the Fast Secure Message Check, from the position corresponding to the length of
			// The byte array of the size of the Fast Secure Message Check		
			System.arraycopy(this.sizeOfSecureMessageHeaderSerialized, 0, this.secureMessageMetaHeaderSerialized,
	        				 serializationOffset, this.sizeOfFastSecureMessageCheckSerialized.length);
			serializationOffset += CommonUtils.INTEGER_LENGTH;
			
			// Fills the byte array of the Secure Message Meta Header with an outside separator,
			// From the position corresponding to the length of 2 (outside separator)
			System.arraycopy(outsideSeparator, 0, this.secureMessageMetaHeaderSerialized, serializationOffset, CommonUtils.META_HEADER_OUTSIDE_SEPARATORS_LENGTH);
			serializationOffset += CommonUtils.META_HEADER_OUTSIDE_SEPARATORS_LENGTH;
		}
	}
	
	public byte[] getSecureMessageMetaHeaderSerialized() {
		return this.isSecureMessageMetaHeaderSerialized ? this.secureMessageMetaHeaderSerialized : null;
	}
}