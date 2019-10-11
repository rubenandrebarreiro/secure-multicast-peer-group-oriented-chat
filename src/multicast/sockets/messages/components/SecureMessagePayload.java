package multicast.sockets.messages.components;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

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
								byte[] messageSerialized) {
		
		this.fromPeerID = fromPeerID;
		this.sequenceNumber = sequenceNumber;
		this.randomNonce = randomNonce;
		this.messageSerialized = messageSerialized;
		
		this.buildIntegrityControlHashSerialized(messageSerialized);
	
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
	
	public void buildIntegrityControlHashSerialized(byte[] messageSerialized) {
		if(messageSerialized != null) {
			try {
				MessageDigest hashFunctionAlgorithmn = MessageDigest.getInstance("SHA-256");
				
				this.integrityControlHashSerialiazed = hashFunctionAlgorithmn.digest(messageSerialized);
			}
			catch (NoSuchAlgorithmException noSuchAlgorithmException) {
				System.err.println("Error occurred during the Hash Function over the Message:");
				System.err.println("- Cryptographic Algorithm not found!!!");
				noSuchAlgorithmException.printStackTrace();
			}
		}
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
	
	public byte[] buildFinalSecureMessagePayloadSerializationSymmetricEncryptionCiphered() {
		this.buildSecureMessagePayloadSerialization();
		
		if(this.isSecureMessagePayloadSerialized) {
			byte[] secureMessageAttributesSerialized = this.getSecureMessagePayloadSerialized();
			
			try {
				
				// TODO - Retirar depois
				// The byte stream input to generate a Secret Key
				// ( 4 x 8 = 32 bytes = 32 x 8 = 256 bits ),
				// because 1 byte is equal to 8 bits 
				byte[] secretKeyBytes = new byte[] { 0x01, 0x23, 0x45, 0x67, (byte)0x89, (byte)0xab,(byte)0xcd, (byte)0xef, 
													 0x01, 0x23, 0x45, 0x67, (byte)0x89, (byte)0xab,(byte)0xcd, (byte)0xef, 
													 0x01, 0x23, 0x45, 0x67, (byte)0x89, (byte)0xab,(byte)0xcd, (byte)0xef ,
													 0x01, 0x23, 0x45, 0x67, (byte)0x89, (byte)0xab,(byte)0xcd, (byte)0xef };
				
		        // The Initialization Vector bytes to be used (with 128-bit size)
				byte[] initialisingVectorBytes = new byte[] { 0x08, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 ,
			                         						   0x08, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 };
				
		        // Set the Secret Key and its specifications,
		 		// using the AES (Advanced Encryption Standard - Rijndael) Symmetric Encryption
		 	    SecretKeySpec secretKeySpecifications = new SecretKeySpec(secretKeyBytes, "AES");

				// The parameter specifications for the Initialization Vector
				IvParameterSpec initializationVectorParameterSpecifications = new IvParameterSpec(initialisingVectorBytes);
				
				Cipher secureMessagePayloadSerializationSymmetricEncryptionCipher = Cipher.getInstance("AES/CTR/PKCSPadding", "BC");
				
				// TODO verificar se o modo em uso necessita de IV
				secureMessagePayloadSerializationSymmetricEncryptionCipher.init(Cipher.ENCRYPT_MODE, secretKeySpecifications, initializationVectorParameterSpecifications);
			
				return secureMessagePayloadSerializationSymmetricEncryptionCipher.doFinal(secureMessageAttributesSerialized);
			
			}
			catch (NoSuchAlgorithmException noSuchAlgorithmException) {
				System.err.println("Error occurred during the Symmetric Encryption over the Secure Message's Payload:");
				System.err.println("- Cryptographic Algorithm not found!!!");
				noSuchAlgorithmException.printStackTrace();
			}
			catch (InvalidAlgorithmParameterException invalidAlgorithmParameterException) {
				System.err.println("Error occurred during the Symmetric Encryption over the Secure Message's Payload:");
				System.err.println("- Invalid Cryptographic Algorithm's Parameters!!!");
				invalidAlgorithmParameterException.printStackTrace();
			}
			catch (NoSuchProviderException noSuchProviderException) {
				System.err.println("Error occurred during the Symmetric Encryption over the Secure Message's Payload:");
				System.err.println("- Cryptograhic Provider not found!!!");
				noSuchProviderException.printStackTrace();
			}
			catch (NoSuchPaddingException noSuchPaddingException) {
				System.err.println("Error occurred during the Symmetric Encryption over the Secure Message's Payload:");
				System.err.println("- Padding Method not found!!!");
				noSuchPaddingException.printStackTrace();
			}
			catch (BadPaddingException badPaddingException) {
				System.err.println("Error occurred during the Symmetric Encryption over the Secure Message's Payload:");
				System.err.println("- Bad/Wrong Padding Method in use!!!");
				badPaddingException.printStackTrace();
			}
			catch (InvalidKeyException invalidKeyException) {
				System.err.println("Error occurred during the Symmetric Encryption over the Secure Message's Payload:");
				System.err.println("- Invalid Cryptographic Algorithm's Secret Key!!!");
				invalidKeyException.printStackTrace();
			}
			catch (IllegalBlockSizeException illegalBlockSizeException) {
				System.err.println("Error occurred during the Symmetric Encryption over the Secure Message's Payload:");
				System.err.println("- Illegal Cryptographic Algorithm's Block Size!!!");
				illegalBlockSizeException.printStackTrace();
			}
		}
		
		return null;
	}
}