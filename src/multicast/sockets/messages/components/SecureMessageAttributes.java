package multicast.sockets.messages.components;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import javax.crypto.Mac;

import multicast.common.CommonUtils;
import multicast.sockets.messages.utils.SecureMulticastChatSessionParameters;

public class SecureMessageAttributes {
	private String sessionID;
	
	private String sessionName;
	
	private String symmetricEncryptionAlgorithm;
	
	private int symmetricEncryptionAlgorithmKeySize;
	
	private String symmetricEncryptionMode;
	
	private String paddingMethod;
	
	private String integrityControlCryptographicHashFunctionConstructionMethod;

	private String fastSecurePayloadCheckMessageAuthenticationCodeConstructionMethod;
	
	private int fastSecurePayloadCheckMessageAuthenticationCodeConstructionMethodKeySize;

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
	
	
	public SecureMessageAttributes(String sessionID, String sessionName, 
								   String symmetricEncryptionAlgorithm,
								   int symmetricEncryptionAlgorithmKeySize,
								   String symmetricEncryptionMode, 
								   String paddingMethod,
								   String integrityControlCryptographicHashFunctionConstructionMethod,
								   String fastSecurePayloadCheckMessageAuthenticationCodeConstructionMethod,
								   int fastSecurePayloadCheckMessageAuthenticationCodeConstructionMethodKeySize) {
		
		this.sessionID = sessionID;
		this.sessionName = sessionName;
		
		this.symmetricEncryptionAlgorithm = symmetricEncryptionAlgorithm;
		this.symmetricEncryptionAlgorithmKeySize = symmetricEncryptionAlgorithmKeySize;
		this.symmetricEncryptionMode = symmetricEncryptionMode;
		
		this.paddingMethod = paddingMethod;
		
		this.integrityControlCryptographicHashFunctionConstructionMethod = integrityControlCryptographicHashFunctionConstructionMethod;
		this.fastSecurePayloadCheckMessageAuthenticationCodeConstructionMethod = fastSecurePayloadCheckMessageAuthenticationCodeConstructionMethod;
		this.fastSecurePayloadCheckMessageAuthenticationCodeConstructionMethodKeySize = fastSecurePayloadCheckMessageAuthenticationCodeConstructionMethodKeySize;
		
		this.isSecureMessageAttributesSerialized = false;
		this.isSecureMessageAttributesSerializedHashed = false;
		
		this.isSecureMessageAttributesCheckValid = false;
		this.isSecureMessageAttributesCheckDone = false;
		
		this.secureMessageAttributesParameters = null;
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
			byte[] secureMessageAttributesSerialized = this.getSecureMessageAttributesSerialized();
						
			// HASHING Process
			try {
				// The Source/Seed of a Secure Random
				SecureRandom secureRandom = new SecureRandom();
												
				// The Initialization Vector and its Parameter's Specifications
				
				Key secureMessageAttributesSerializationHashKey = 
						CommonUtils.createKeyForAES(this.fastSecurePayloadCheckMessageAuthenticationCodeConstructionMethodKeySize,
													secureRandom);
				//Key secureMessageAttributesSerializationHashKey = null;  // TODO
				Mac mac = Mac.getInstance(this.fastSecurePayloadCheckMessageAuthenticationCodeConstructionMethod);
				mac.init(secureMessageAttributesSerializationHashKey);
				mac.update(secureMessageAttributesSerialized);
				
				this.secureMessageAttributesSerializedHashed = mac.doFinal();
			}
			catch (NoSuchAlgorithmException noSuchAlgorithmException) {
				System.err.println("Error occurred during the Hashing Function over the Secure Message's Attributes:");
				System.err.println("- Cryptographic Algorithm not found!!!");
				noSuchAlgorithmException.printStackTrace();
			}
			catch (NoSuchProviderException noSuchProviderException) {
				System.err.println("Error occurred during the Hashing Function over the Secure Message's Attributes:");
				System.err.println("- Cryptograhic Provider not found!!!");
				noSuchProviderException.printStackTrace();
			}
			catch (InvalidKeyException invalidKeyException) {
				System.err.println("Error occurred during the Hashing Function over the Secure Message's Attributes:");
				System.err.println("- Invalid Secret Key!!!");
				invalidKeyException.printStackTrace();
			}
		
			this.isSecureMessageAttributesSerializedHashed = true;
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
				
				
				// HASHING Process
				try {
					// The Source/Seed of a Secure Random
					SecureRandom secureRandom = new SecureRandom();
					
					// The Initialization Vector and its Parameter's Specifications
					Key secureMessageAttributesSerializationHashKey = 
							CommonUtils.createKeyForAES(Integer.parseInt(this.secureMessageAttributesParameters.getProperty("macks")),
														secureRandom);
					
					Mac mac = Mac.getInstance(this.secureMessageAttributesParameters.getProperty("mac"));
					mac.init(secureMessageAttributesSerializationHashKey);
					mac.update(this.secureMessageAttributesSerializedHashedToCompare);
					
					secureMessageAttributesSerializedHashedToCompare = mac.doFinal();
				}
				catch (NoSuchAlgorithmException noSuchAlgorithmException) {
					System.err.println("Error occurred during the Hashing Function over the Secure Message's Attributes:");
					System.err.println("- Cryptographic Algorithm not found!!!");
					noSuchAlgorithmException.printStackTrace();
				}
				catch (NoSuchProviderException noSuchProviderException) {
					System.err.println("Error occurred during the Hashing Function over the Secure Message's Attributes:");
					System.err.println("- Cryptograhic Provider not found!!!");
					noSuchProviderException.printStackTrace();
				}
				catch (InvalidKeyException invalidKeyException) {
					System.err.println("Error occurred during the Hashing Function over the Secure Message's Attributes:");
					System.err.println("- Invalid Secret Key!!!");
					invalidKeyException.printStackTrace();
				}
				
				this.isSecureMessageAttributesCheckValid = (this.isSecureMessageAttributesSerializedHashed &&
						this.secureMessageAttributesSerializedHashed.equals(secureMessageAttributesSerializedHashedToCompare)) ? 
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