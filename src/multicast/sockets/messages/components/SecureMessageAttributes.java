package multicast.sockets.messages.components;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import multicast.common.CommonUtils;
import multicast.sockets.messages.utils.SecureMulticastChatSessionParameters;

public class SecureMessageAttributes {
	private String sessionID;
	
	private String sessionName;
	
	private String symmetricEncryptionAlgorithm;
	
	private String symmetricEncryptionMode;
	
	private String paddingMethod;
	
	private String integrityControlCryptographicHashFunctionConstructionMethod;

	private String fastSecurePayloadCheckMessageAuthenticationCodeConstructionMethod;
	
	/**
	 * The (Secure) Multicast Chat Session's Parameters,
	 * loaded from the User (Client) sending this Secure Message,
	 * which will be used in the Secure Message's Attributes
	 */
	private SecureMulticastChatSessionParameters secureMessageAttributesParameters;
	
	private byte[] secureMessageAttributesSerialized;
	
	private boolean isSecureMessageAttributesSerialized;
	
	private byte[] secureMessageAttributesSerializedHashed;
	
	private boolean isSecureMessageAttributesSerializedHashed;
		
	private boolean isSecureMessageAttributesCheckValid;
	
	private boolean isSecureMessageAttributesCheckDone;
	
	
	public SecureMessageAttributes(SecureMulticastChatSessionParameters secureMessageAttributesParameters) {
		
		this.secureMessageAttributesParameters = secureMessageAttributesParameters;
		
		this.sessionID = this.secureMessageAttributesParameters.getProperty("sid");
		this.sessionName = this.secureMessageAttributesParameters.getProperty("sid");
		
		this.symmetricEncryptionAlgorithm = this.secureMessageAttributesParameters.getProperty("sea");
		this.symmetricEncryptionMode = this.secureMessageAttributesParameters.getProperty("mode");
		this.paddingMethod = this.secureMessageAttributesParameters.getProperty("padding");
		
		this.integrityControlCryptographicHashFunctionConstructionMethod = this.secureMessageAttributesParameters.getProperty("inthash");
		this.fastSecurePayloadCheckMessageAuthenticationCodeConstructionMethod = this.secureMessageAttributesParameters.getProperty("mac");
				
		this.isSecureMessageAttributesSerialized = false;
		this.isSecureMessageAttributesSerializedHashed = false;
		
		this.isSecureMessageAttributesCheckValid = false;
		this.isSecureMessageAttributesCheckDone = false;
		
	}
	
	public SecureMessageAttributes(byte[] secureMessageAttributesSerializedHashed,
								   SecureMulticastChatSessionParameters secureMessageAttributesParameters) {
		
		this.secureMessageAttributesSerializedHashed = secureMessageAttributesSerializedHashed;
		
		this.isSecureMessageAttributesSerialized = true;
		this.isSecureMessageAttributesSerializedHashed = true;
		
		this.secureMessageAttributesParameters = secureMessageAttributesParameters;
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
	
	public String getIntegrityControlCryptographicHashFunctionConstructionMethod() {
		return this.integrityControlCryptographicHashFunctionConstructionMethod;
	}
	
	public String getFastSecurePayloadCheckMessageAuthenticationCodeConstructionMethod() {
		return this.fastSecurePayloadCheckMessageAuthenticationCodeConstructionMethod;
	}

	public void buildSecureMessageAttributesSerialized() {
		if(!this.isSecureMessageAttributesSerialized) {
			
			byte[] sessionIDSerialized = CommonUtils.fromStringToByteArray(this.sessionID);
			
			byte[] sessionNameSerialized = CommonUtils.fromStringToByteArray(this.sessionName);
			
			byte[] symmetricEncryptionAlgorithmSerialized = CommonUtils.fromStringToByteArray(this.symmetricEncryptionAlgorithm);
			
			byte[] symmetricEncryptionModeSerialized = CommonUtils.fromStringToByteArray(this.symmetricEncryptionMode);
			
			byte[] paddingMethodSerialized = CommonUtils.fromStringToByteArray(this.paddingMethod);
			
			byte[] integrityControlCryptographicHashFunctionConstructionMethodSerialized = 
															CommonUtils.fromStringToByteArray(this.integrityControlCryptographicHashFunctionConstructionMethod);
			
			byte[] fastSecurePayloadCheckMessageAuthenticationCodeConstructionMethodSerialized = 
															CommonUtils.fromStringToByteArray(this.fastSecurePayloadCheckMessageAuthenticationCodeConstructionMethod);
			
			
			int sizeOfSecureMessageAtrributesSerialized = ( sessionIDSerialized.length + sessionNameSerialized.length + 
					                                        symmetricEncryptionAlgorithmSerialized.length + symmetricEncryptionModeSerialized.length + paddingMethodSerialized.length + 
					                                        integrityControlCryptographicHashFunctionConstructionMethodSerialized.length + 
					                                        fastSecurePayloadCheckMessageAuthenticationCodeConstructionMethodSerialized.length );
						
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
			System.arraycopy(integrityControlCryptographicHashFunctionConstructionMethodSerialized, 0, this.secureMessageAttributesSerialized, serializationOffset,
					         integrityControlCryptographicHashFunctionConstructionMethodSerialized.length);
			serializationOffset += integrityControlCryptographicHashFunctionConstructionMethodSerialized.length;
						
			// Fills the byte array of the Secure Message Attributes with the serialization of the name of Fast Secure Payload Check Construction Mode in use,
			// From the position corresponding to the length of the byte array of the name of Fast Secure Payload Check Construction Mode in use
			System.arraycopy(fastSecurePayloadCheckMessageAuthenticationCodeConstructionMethodSerialized, 0, this.secureMessageAttributesSerialized, serializationOffset,
							 fastSecurePayloadCheckMessageAuthenticationCodeConstructionMethodSerialized.length);
			serializationOffset += fastSecurePayloadCheckMessageAuthenticationCodeConstructionMethodSerialized.length;
						
			this.isSecureMessageAttributesSerialized = true;
		}	
	}
	
	public byte[] getSecureMessageAttributesSerialized() {
		return this.isSecureMessageAttributesSerialized ? this.secureMessageAttributesSerialized : null;
	}
	
	public byte[] getSecureMessageAttributesSerializedHashed() {
		return this.isSecureMessageAttributesSerializedHashed ? this.secureMessageAttributesSerializedHashed : null;
	}
	
	public void buildFinalSecureMessageAttributesSerializedHashed() {
		
		// TODO
		if(this.isSecureMessageAttributesSerialized && !this.isSecureMessageAttributesSerializedHashed) {
			this.getSecureMessageAttributesSerialized();
						
			// HASHING Process
			try {
				
				MessageDigest hashFunctionAlgorithm = MessageDigest.getInstance(this.secureMessageAttributesParameters.getProperty("inthash"));
				this.secureMessageAttributesSerializedHashed = hashFunctionAlgorithm.digest(this.secureMessageAttributesSerialized);
				this.isSecureMessageAttributesSerializedHashed = true;

			} catch (Exception e) {
				// TODO: handle exception
			}
		
		}
	}
	
	public boolean checkIfIsSecureMessageAttributesSerializedHashedValid() {
		if(!this.isSecureMessageAttributesCheckDone) {
			
			if(this.isSecureMessageAttributesSerialized && this.isSecureMessageAttributesSerializedHashed) {
				
				//this.sessionID = String.format("%s:%s", this.secureMessageAttributesParameters.getProperty("ip"),
				//									    this.secureMessageAttributesParameters.getProperty("port"));
				
				this.sessionID = this.secureMessageAttributesParameters.getProperty("sid");
				this.sessionName = this.secureMessageAttributesParameters.getProperty("sid");
				
				this.symmetricEncryptionAlgorithm = this.secureMessageAttributesParameters.getProperty("sea");
				this.symmetricEncryptionMode = this.secureMessageAttributesParameters.getProperty("mode");
				this.paddingMethod = this.secureMessageAttributesParameters.getProperty("padding");
				
				this.integrityControlCryptographicHashFunctionConstructionMethod = this.secureMessageAttributesParameters.getProperty("inthash");
				this.fastSecurePayloadCheckMessageAuthenticationCodeConstructionMethod = this.secureMessageAttributesParameters.getProperty("mac");
				
				
				
				
				byte[] sessionIDSerialized = CommonUtils.fromStringToByteArray(this.sessionID);
				
				byte[] sessionNameSerialized = CommonUtils.fromStringToByteArray(this.sessionName);
				
				byte[] symmetricEncryptionAlgorithmSerialized = CommonUtils.fromStringToByteArray(this.symmetricEncryptionAlgorithm);
				
				byte[] symmetricEncryptionModeSerialized = CommonUtils.fromStringToByteArray(this.symmetricEncryptionMode);
				
				byte[] paddingMethodSerialized = CommonUtils.fromStringToByteArray(this.paddingMethod);
				
				byte[] integrityControlCryptographicHashFunctionConstructionMethodSerialized = 
																CommonUtils.fromStringToByteArray(this.integrityControlCryptographicHashFunctionConstructionMethod);
				
				byte[] fastSecurePayloadCheckMessageAuthenticationCodeConstructionMethodSerialized = 
																CommonUtils.fromStringToByteArray(this.fastSecurePayloadCheckMessageAuthenticationCodeConstructionMethod);
				
				
				int sizeOfSecureMessageAtrributesSerialized = ( sessionIDSerialized.length + sessionNameSerialized.length + 
						                                        symmetricEncryptionAlgorithmSerialized.length + symmetricEncryptionModeSerialized.length + paddingMethodSerialized.length + 
						                                        integrityControlCryptographicHashFunctionConstructionMethodSerialized.length + 
						                                        fastSecurePayloadCheckMessageAuthenticationCodeConstructionMethodSerialized.length );
							
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
				System.arraycopy(integrityControlCryptographicHashFunctionConstructionMethodSerialized, 0, this.secureMessageAttributesSerialized, serializationOffset,
						         integrityControlCryptographicHashFunctionConstructionMethodSerialized.length);
				serializationOffset += integrityControlCryptographicHashFunctionConstructionMethodSerialized.length;
							
				// Fills the byte array of the Secure Message Attributes with the serialization of the name of Fast Secure Payload Check Construction Mode in use,
				// From the position corresponding to the length of the byte array of the name of Fast Secure Payload Check Construction Mode in use
				System.arraycopy(fastSecurePayloadCheckMessageAuthenticationCodeConstructionMethodSerialized, 0, this.secureMessageAttributesSerialized, serializationOffset,
								 fastSecurePayloadCheckMessageAuthenticationCodeConstructionMethodSerialized.length);
				serializationOffset += fastSecurePayloadCheckMessageAuthenticationCodeConstructionMethodSerialized.length;
				
				
				
				
				byte[] secureMessageAttributesSerializedHashedToCompare = null;
				

				// HASHING Process

				// The configuration, initialization and update of the Integrity Control Hash process
				try {
					MessageDigest hashFunctionAlgorithmn = MessageDigest.getInstance(this.secureMessageAttributesParameters.getProperty("inthash"));
					secureMessageAttributesSerializedHashedToCompare = hashFunctionAlgorithmn.digest(this.secureMessageAttributesSerialized);
				} catch (NoSuchAlgorithmException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

				// Performs the final operation of Integrity Control Hash process over the Message serialized


				this.isSecureMessageAttributesCheckValid = (this.isSecureMessageAttributesSerializedHashed &&
						Arrays.equals(this.secureMessageAttributesSerializedHashed, secureMessageAttributesSerializedHashedToCompare)) ? 
								true : false;

				if(!this.isSecureMessageAttributesCheckValid) {
					System.err.println("The Secure Message's Attributes for the current Session aren't valid:");
					System.err.println("- The Secure Message will be ignored!!!");
				}
				
				this.isSecureMessageAttributesCheckDone = true;

				// Returns true if the hash performed/computed over Secure Message serialized received its valid,
				// comparing it with the Secure Message serialized hashed received and false, otherwise
				return this.isSecureMessageAttributesCheckValid;
			}
			
			return false;
		}
		else {
			return this.isSecureMessageAttributesCheckValid;
		}
	}
}