package multicast.sockets.messages.components;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import javax.crypto.Mac;

import multicast.common.CommonUtils;

public class FastSecureMessageCheck {
	
	// Global Instance Variables:
	
	/**
	 * 
	 */
	private byte[] secureMessageSerialized;
	
	/**
	 * 
	 */
	private byte[] secureMessageSerializedHashed;
	
	/**
	 * 
	 */
	private boolean isSecureMessageSerializedHashed;
	
	/**
	 * 
	 */
	private boolean isSecureMessageSerializedHashedValid;
	
	// Constructors:
	/**
	 * Constructor #1:
	 * - TODO
	 * 
	 * @param secureMessageSerialized
	 */
	public FastSecureMessageCheck(byte[] secureMessageSerialized) {
		this.secureMessageSerialized = secureMessageSerialized;
		
		this.isSecureMessageSerializedHashed = false;
	}
	
	/**
	 * Constructor #2:
	 * - TODO
	 * @param secureMessageSerialized
	 * 
	 * @param secureMessageSerializedHashed
	 */
	public FastSecureMessageCheck(byte[] secureMessageSerialized, byte[] secureMessageSerializedHashed) {
		this.secureMessageSerialized = secureMessageSerialized;
		this.secureMessageSerializedHashed = secureMessageSerializedHashed;
		
		// TODO comparar com o hash da secure message
		this.isSecureMessageSerializedHashedValid = 
									this.secureMessageSerializedHashed.equals(null) ? true : false;
		
		this.isSecureMessageSerializedHashed = true;
	}
	
	public byte[] getSecureMessageSerialized() {
		return this.secureMessageSerialized;
	}
	
	public void buildSecureMessageSerializedHashed() {
		
		if(!this.isSecureMessageSerializedHashed) {
			byte[] secureMessageAttributesSerialized = this.getSecureMessageSerialized();
			
			// HASHING Process
			try {
				// The Source/Seed of a Secure Random
				SecureRandom secureRandom = new SecureRandom();
				
				// The Initialization Vector and its Parameter's Specifications
				Key secureMessageAttributesSerializationHashKey = CommonUtils.createKeyForAES(256, secureRandom);
				
				//Key secureMessageAttributesSerializationHashKey = null;  // TODO
				Mac mac = Mac.getInstance("SHA-256");
				mac.init(secureMessageAttributesSerializationHashKey);
				mac.update(secureMessageAttributesSerialized);
				
				this.secureMessageSerializedHashed = mac.doFinal();
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
		
			this.isSecureMessageSerializedHashed = true;
		}
	}
	
	public byte[] getSecureMessageSerializedHashed() {
		return this.isSecureMessageSerializedHashed ? this.secureMessageSerializedHashed : null;
	}
	
	public boolean checkIfIsSecureMessageSerializedHashedValid() {
		return this.isSecureMessageSerializedHashedValid;
	}
}