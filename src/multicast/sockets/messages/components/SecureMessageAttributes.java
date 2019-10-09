package multicast.sockets.messages.components;

import multicast.common.CommonUtils;

public class SecureMessageAttributes {
	private String sessionID;
	
	private String sessionName;
	
	private String symmetricEncryptionAlgorithm;
	
	private String symmetricEncryptionMode;
	
	private String paddingMethod;
	
	private String integrityControlConstructionMethod;

	private String fastSecurePayloadCheckConstructionMethod;

	private byte[] secureMessageAttributesSerialized;
	
	private boolean isSecureMessageAttributesSerialized;
	
	
	public SecureMessageAttributes(String sessionID, String sessionName, 
								   String symmetricEncryptionAlgorithm,
								   String symmetricEncryptionMode, 
								   String paddingMethod,
								   String integrityControlConstructionMethod,
								   String fastSecurePayloadCheckConstructionMethod) {
		
		this.sessionID = sessionID;
		this.sessionName = sessionName;
		
		this.symmetricEncryptionAlgorithm = symmetricEncryptionAlgorithm;
		this.symmetricEncryptionMode = symmetricEncryptionMode;
		
		this.paddingMethod = paddingMethod;
		
		this.integrityControlConstructionMethod = integrityControlConstructionMethod;
		this.fastSecurePayloadCheckConstructionMethod = fastSecurePayloadCheckConstructionMethod;
		
		this.isSecureMessageAttributesSerialized = false;
	}
	
	public String getSessionID() {
		return this.sessionID;
	}
	
	public String getSessionName() {
		return this.sessionName;
	}
	
	public String getSymmetricEncryptionAlgorithm() {
		return this.symmetricEncryptionAlgorithm;
	}
	
	public String getSymmetricEncryptionMode() {
		return this.symmetricEncryptionMode;
	}
	
	public String getPaddingMethod() {
		return this.paddingMethod;
	}
	
	public String getIntegrityControlConstructionMethod() {
		return this.integrityControlConstructionMethod;
	}
	
	public String getFastSecurePayloadCheckConstructionMethod() {
		return this.fastSecurePayloadCheckConstructionMethod;
	}

	public void buildSecureMessageAttributesSerialization() {
		if(!this.isSecureMessageAttributesSerialized) {
			
			byte[] sessionIDSerialized = CommonUtils.fromStringToByteArray(this.sessionID);
			
			byte[] sessionNameSerialized = CommonUtils.fromStringToByteArray(this.sessionName);
			
			byte[] symmetricEncryptionAlgorithmSerialized = CommonUtils.fromStringToByteArray(this.symmetricEncryptionAlgorithm);
			
			byte[] symmetricEncryptionModeSerialized = CommonUtils.fromStringToByteArray(this.symmetricEncryptionMode);
			
			byte[] paddingMethodSerialized = CommonUtils.fromStringToByteArray(this.paddingMethod);
			
			byte[] integrityControlConstructionMethodSerialized = CommonUtils.fromStringToByteArray(this.integrityControlConstructionMethod);
			
			byte[] fastSecurePayloadCheckConstructionMethodSerialized = CommonUtils.fromStringToByteArray(this.fastSecurePayloadCheckConstructionMethod);
			
			
			int sizeOfSecureMessageAtrributesSerialized = ( sessionIDSerialized.length + sessionNameSerialized.length + 
					                                        symmetricEncryptionAlgorithmSerialized.length + symmetricEncryptionModeSerialized.length + paddingMethodSerialized.length + 
					                                        integrityControlConstructionMethodSerialized.length + fastSecurePayloadCheckConstructionMethodSerialized.length );

			this.secureMessageAttributesSerialized = new byte[sizeOfSecureMessageAtrributesSerialized];
			
			int serializationOffset = 0;

			// Fills the byte array of the Secure Message Attributes with the serialization of the Session's ID,
			// From the position corresponding to the length of the byte array of the Session's ID			
			System.arraycopy(sessionIDSerialized, 0, this.secureMessageAttributesSerialized, 0, sessionIDSerialized.length);
			serializationOffset += sessionIDSerialized.length;
			
			// Fills the byte array of the Secure Message Attributes with the serialization of the Session's Name,
			// From the position corresponding to the length of the byte array of the Session's Name
			System.arraycopy(sessionNameSerialized, 0, this.secureMessageAttributesSerialized, serializationOffset, sessionNameSerialized.length);
			serializationOffset += sessionNameSerialized.length;
			
			// Fills the byte array of the Secure Message Attributes with the serialization of the name of Symmetric Encryption Algorithm in use,
			// From the position corresponding to the length of the byte array of the name of Symmetric Encryption Algorithm in use
			System.arraycopy(symmetricEncryptionAlgorithmSerialized, 0, this.secureMessageAttributesSerialized, serializationOffset, symmetricEncryptionAlgorithmSerialized.length);
			serializationOffset += symmetricEncryptionAlgorithmSerialized.length;
			
			// Fills the byte array of the Secure Message Attributes with the serialization of the name of Symmetric Encryption Mode in use,
			// From the position corresponding to the length of the byte array of the name of Symmetric Encryption Mode in use
			System.arraycopy(symmetricEncryptionModeSerialized, 0, this.secureMessageAttributesSerialized, serializationOffset, symmetricEncryptionModeSerialized.length);
			serializationOffset += symmetricEncryptionModeSerialized.length;
			
			// Fills the byte array of the Secure Message Attributes with the serialization of the name of Padding Mode in use,
			// From the position corresponding to the length of the byte array of the name of Symmetric Padding Mode in use
			System.arraycopy(paddingMethodSerialized, 0, this.secureMessageAttributesSerialized, serializationOffset, paddingMethodSerialized.length);
			serializationOffset += paddingMethodSerialized.length;
			
			// Fills the byte array of the Secure Message Attributes with the serialization of the name of Integrity Control Construction Mode in use,
			// From the position corresponding to the length of the byte array of the name of Integrity Control Construction Mode in use		
			System.arraycopy(integrityControlConstructionMethodSerialized, 0, this.secureMessageAttributesSerialized, serializationOffset,
					         integrityControlConstructionMethodSerialized.length);
			serializationOffset += integrityControlConstructionMethodSerialized.length;
			
			// Fills the byte array of the Secure Message Attributes with the serialization of the name of Fast Secure Payload Check Construction Mode in use,
			// From the position corresponding to the length of the byte array of the name of Fast Secure Payload Check Construction Mode in use
			System.arraycopy(fastSecurePayloadCheckConstructionMethodSerialized, 0, this.secureMessageAttributesSerialized, serializationOffset,
					         fastSecurePayloadCheckConstructionMethodSerialized.length);
			serializationOffset += fastSecurePayloadCheckConstructionMethodSerialized.length;
						
			this.isSecureMessageAttributesSerialized = true;
		}	
	}
	
	public byte[] getSecureMessageAttributesSerialized() {
		return this.isSecureMessageAttributesSerialized ? this.secureMessageAttributesSerialized : null;
	}
}