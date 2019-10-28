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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import multicast.common.CommonUtils;
import multicast.sockets.messages.utils.KeyStoreInterface;
import multicast.sockets.messages.utils.SecureMulticastChatSessionParameters;

/**
 * 
 * Class for the Secure Message's Payload.
 * 
 * @supervisor Prof. Henrique Joao Domingos - hj@fct.unl.pt
 * 
 * @author Eduardo Bras Silva (no. 41798) - emf.silva@campus.fct.unl.pt
 * @author Ruben Andre Barreiro (no. 42648) - r.barreiro@campus.fct.unl.pt
 *
 */
public class SecureMessagePayload {
	
	// Global Instance Variables:
	/**
	 * The ID of the Sender's Peer,
	 * which sent the Secure Message Payload
	 */
	private String fromPeerID;
	
	/**
	 * The Sequence Number of the Secure Message's Payload
	 */
	private int sequenceNumber;
	
	/**
	 * The Random Nonce of the Secure Message's Payload
	 */
	private int randomNonce;
	
	/**
	 * The Message (i.e., the real content of the Message) of
	 * the Secure Message's Payload
	 */
	private byte[] messageSerialized;
	
	/**
	 * The Integrity Control Hashed serialized of the Secure Message's Payload
	 */
	private byte[] integrityControlHashedSerialized;
	
	/**
	 * The boolean to keep the value to check if
	 * the Integrity Control Hashed serialized is done
	 */
	private boolean isIntegrityControlHashedSerialized;
	
	/**
	 * The Secure Message's Payload serialized
	 */
	private byte[] secureMessagePayloadSerialized;
	
	/**
	 * The boolean to keep the value to check if
	 * the Secure Message's Payload is serialized
	 */
	private boolean isSecureMessagePayloadSerialized;
	
	/**
	 * The Secure Message's Payload serialized and Symmetric Encryption Ciphered 
	 */
	private byte[] secureMessagePayloadSerializedSymmetricEncryptionCiphered;
	
	/**
	 * The boolean to keep the value to check if
	 * the Secure Message's Payload is serialized and Symmetric Encryption Ciphered
	 */
	private boolean isSecureMessagePayloadSerializedSymmetricEncryptionCiphered;
	
	/**
	 * Encryption provider
	 */
	private static final String provider = "BC";

	/**
	 * Properties Reader from file
	 */
	private SecureMulticastChatSessionParameters secureMessageAttributesParameters;
	
	/**
	 * Keystore interface
	 */
	private KeyStoreInterface keystoreInterface;
	
	/**
	 * Filename of Properties' file
	 */
	private static final String propertiesFilename = "./res/SMCP.conf";
	
	/**
	 * Filename of Keystore file
	 */
	private static final String keystoreFilename = "./res/SMCPKeystore.jecks";

	
	
	
	// Constructors:
	/**
	 * Constructor #1:
	 * - The Constructor of the Secure Message's Payload,
	 *   from the respectively basic components of it.
	 * 
	 * @param fromPeerID the ID of the Sender's Peer,
	 * 		  which sent the Secure Message Payload
	 * 
	 * @param sequenceNumber the Sequence Number of the Secure Message's Payload
	 * 
	 * @param randomNonce the Random Nonce of the Secure Message's Payload
	 * 
	 * @param messageSerialized the Message (i.e., the real content of the Message) of
	 * 		  the Secure Message's Payload
	 */
	public SecureMessagePayload(String fromPeerID, int sequenceNumber, int randomNonce,
								byte[] messageSerialized) {
		
		this.fromPeerID = fromPeerID;
		this.sequenceNumber = sequenceNumber;
		this.randomNonce = randomNonce;
		this.messageSerialized = messageSerialized;
		
		this.isIntegrityControlHashedSerialized = false;
		this.isSecureMessagePayloadSerialized = false;
		this.isSecureMessagePayloadSerializedSymmetricEncryptionCiphered = false;
		
		this.secureMessageAttributesParameters = new SecureMulticastChatSessionParameters(propertiesFilename);
	
		this.keystoreInterface = new KeyStoreInterface(keystoreFilename, "CSNS1920");
	}
	
	/**
	 * Constructor #2:
	 * - The Constructor of the Secure Message's Payload,
	 *   from the Secure Message's Payload serialized and Symmetric Encryption Ciphered.
	 * 
	 * @param secureMessagePayloadSerializedSymmetricEncryptionCiphered the Secure Message's Payload serialized
	 *        and Symmetric Encryption Ciphered 
	 */
	public SecureMessagePayload(byte[] secureMessagePayloadSerializedSymmetricEncryptionCiphered) {
		this.secureMessagePayloadSerializedSymmetricEncryptionCiphered = 
						secureMessagePayloadSerializedSymmetricEncryptionCiphered;
		
		this.isIntegrityControlHashedSerialized = true;
		this.isSecureMessagePayloadSerialized = true;
		this.isSecureMessagePayloadSerializedSymmetricEncryptionCiphered = true;
		
		this.keystoreInterface = new KeyStoreInterface(keystoreFilename, "CSNS1920");
	}
	
	
	
	// Methods:
	/**
	 * Returns the ID of the Sender's Peer,
	 * which sent the Secure Message Payload.
	 * 
	 * @return the ID of the Sender's Peer,
	 * 		   which sent the Secure Message Payload
	 */
	public String getFromPeerID() {
		return this.isSecureMessagePayloadSerialized ? null : this.fromPeerID;
	}
	
	/**
	 * Returns the Sequence Number of the Secure Message's Payload.
	 * 
	 * @return the Sequence Number of the Secure Message's Payload
	 */
	public int getSequenceNumber() {
		return this.isSecureMessagePayloadSerialized ? null : this.sequenceNumber;
	}
	
	/**
	 * Returns the Random Nonce of the Secure Message's Payload.
	 * 
	 * @return the Random Nonce of the Secure Message's Payload
	 */
	public int getRandomNonce() {
		return this.isSecureMessagePayloadSerialized ? null : this.randomNonce;
	}
	
	/**
	 * Returns the Message (i.e., the real content of the Message) of
	 * the Secure Message's Payload.
	 * 
	 * @return the Message (i.e., the real content of the Message) of
	 * 		   the Secure Message's Payload
	 */
	public byte[] getMessageSerialized() {
		return this.isSecureMessagePayloadSerialized ? null : this.messageSerialized;
	}
	
	/**
	 * Builds the Integrity Control Hashed serialized of the Message serialized
     * (i.e., the real content of the Message) of the Secure Message's Payload.
	 * 
	 * @param messageSerialized the Message serialized (i.e., the real content of the Message) of
	 *        the Secure Message's Payload
	 */
	public void buildIntegrityControlHashedSerialized() {
		
		// This process it's only made if the Integrity Control Hashed serialized of the Message
		// (i.e., the real content of the Message) of the Secure Message's Payload it's done
		if(!this.isIntegrityControlHashedSerialized && this.messageSerialized != null) {
			try {
				
				// The configuration, initialization and update of the Integrity Control Hash process
				MessageDigest hashFunctionAlgorithmn = MessageDigest.getInstance(this.secureMessageAttributesParameters.getProperty("inthash"));
				
				// Performs the final operation of Integrity Control Hash process over the Message serialized
				this.integrityControlHashedSerialized = hashFunctionAlgorithmn.digest(this.messageSerialized);
				
				// The Integrity Control Hashed serialized of the Message
			    // (i.e., the real content of the Message) of the Secure Message's Payload it's already done
				this.isIntegrityControlHashedSerialized = true;
			}
			catch (NoSuchAlgorithmException noSuchAlgorithmException) {
				System.err.println("Error occurred during the Hash Function over the Message:");
				System.err.println("- Cryptographic Algorithm not found!!!");
				noSuchAlgorithmException.printStackTrace();
			}
		}
	}
	
	/**
	 * Returns true if the Integrity Control Hashed serialized of the Message
     * (i.e., the real content of the Message) of the Secure Message's Payload it's valid,
	 * comparing it with the Message (i.e., the real content of the Message)
	 * hashed received and false, otherwise.
	 * 
	 * @return true if the Integrity Control Hashed serialized of the Message
     * 		   (i.e., the real content of the Message) of the Secure Message's Payload it's valid,
	 * 		   comparing it with the Message (i.e., the real content of the Message)
	 * 		   hashed received and false, otherwise.
	 */
	public boolean checkIfIsIntegrityControlHashedSerializedValid() {
		
		// This process it's only made if the Integrity Control Hashed serialized of the Message
		// (i.e., the real content of the Message) of the Secure Message's Payload it's done
		if(this.isIntegrityControlHashedSerialized && messageSerialized != null) {
			
			// TODO
			byte[] messageSerializedHashedToCompare = this.messageSerialized;
			
			try {
				
				// The configuration, initialization and update of the Integrity Control Hash process
				MessageDigest hashFunctionAlgorithmn = MessageDigest.getInstance(this.secureMessageAttributesParameters.getProperty("inthash"));
				
				// Performs the final operation of Integrity Control Hash process over the Message serialized
				this.integrityControlHashedSerialized = hashFunctionAlgorithmn.digest(this.messageSerialized);
			}
			catch (NoSuchAlgorithmException noSuchAlgorithmException) {
				System.err.println("Error occurred during the Hash Function over the Message:");
				System.err.println("- Cryptographic Algorithm not found!!!");
				noSuchAlgorithmException.printStackTrace();
			}
			
			// Returns true if the Integrity Control Hash performed/computed over Message serialized received its valid,
			// comparing it with the Message serialized hashed received and false, otherwise
			return (this.isIntegrityControlHashedSerialized && this.integrityControlHashedSerialized.equals(messageSerializedHashedToCompare)) ? 
					true : false;	
		}
		
		return false;
	}
	
	/**
	 * Returns the Integrity Control Hashed serialized of the Message
	 * (i.e., the real content of the Message) of the Secure Message's Payload.
	 * 
	 * @return the Integrity Control Hashed serialized of the Message
	 * 		   (i.e., the real content of the Message) of the Secure Message's Payload
	 */
	public byte[] getIntegrityControlSerialiazedHashed() {
		return this.isIntegrityControlHashedSerialized ? this.integrityControlHashedSerialized : null;
	}
	
	/**
	 * Builds the Secure Message's Payload serialized.
	 */
	public void buildSecureMessagePayloadSerialized() {
		
		// This process it's only made if the Integrity Control Hashed serialized of the Message
		// (i.e., the real content of the Message) of the Secure Message's Payload it's done and
		// the Secure Message's Payload is not serialized
		if(this.isIntegrityControlHashedSerialized && !this.isSecureMessagePayloadSerialized) {
			
			// The ID of the Sender's Peer, which sent the Secure Message Payload serialized
			byte[] fromPeerIDSerialized = this.fromPeerID.getBytes();
			
			// The Sequence Number of the Secure Message's Payload serialized
			byte[] sequenceNumberSerialized = CommonUtils.fromIntToByteArray(sequenceNumber);
			
			// The Random Nonce of the Secure Message's Payload serialized
			byte[] randomNonceSerialized = CommonUtils.fromIntToByteArray(randomNonce);
			
			// The size of the Secure Message's Payload serialized
			int sizeOfSecureMessagePayloadSerialized = ( fromPeerIDSerialized.length + sequenceNumberSerialized.length + randomNonceSerialized.length + 
														 this.messageSerialized.length + this.integrityControlHashedSerialized.length );
			
			// The creation of the Secure Message's Payload serialized
			this.secureMessagePayloadSerialized = new byte[sizeOfSecureMessagePayloadSerialized];
			
			
			// Operations to Fill a Byte Array, with the following parameters:
			// 1) src - The source of the array to be copied
			// 2) srcPos - The position from the array to be copied, representing the first element to be copied
			// 3) dest - The destination of the array to be copied
			// 4) destPos - The position of the array where will be placed the new copy,
			//              representing the first element where new data will be placed
			// 5) length - The length of the data to be copied from the source array to the destination array
				
			// The offset related to fulfillment of the serialization process
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
			System.arraycopy(this.integrityControlHashedSerialized, 0, this.secureMessagePayloadSerialized,
							 serializationOffset, this.integrityControlHashedSerialized.length);
			serializationOffset += this.integrityControlHashedSerialized.length;
			
			
			// The Secure Message's Payload have already its serialization done
			this.isSecureMessagePayloadSerialized = true;
		}
	}
	
	/**
	 * Builds the several components of the Secure Message's Payload serialized. TODO IMPORTANTEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE
	 */
	public void buildSecureMessagePayloadComponents() {
		
		// This process it's only made if the Integrity Control Hashed serialized of the Message
		// (i.e., the real content of the Message) of the Secure Message's Payload is done,
		// the Secure Message's Payload is serialized and its Symmetric Encryption Cipher it's undone
		if(this.isIntegrityControlHashedSerialized && this.isSecureMessagePayloadSerialized &&
		  !this.isSecureMessagePayloadSerializedSymmetricEncryptionCiphered) {
			
			// The ID of the Sender's Peer, which sent the Secure Message Payload serialized TODO
			byte[] fromPeerIDSerialized = this.fromPeerID.getBytes();
			
			// The Sequence Number of the Secure Message's Payload serialized
			byte[] sequenceNumberSerialized = CommonUtils.fromIntToByteArray(sequenceNumber);
			
			// The Random Nonce of the Secure Message's Payload serialized
			byte[] randomNonceSerialized = CommonUtils.fromIntToByteArray(randomNonce);
			
			// The size of the Secure Message's Payload serialized
			int sizeOfSecureMessagePayloadSerialized = ( fromPeerIDSerialized.length + sequenceNumberSerialized.length + randomNonceSerialized.length + 
														 this.messageSerialized.length + this.integrityControlHashedSerialized.length );
			
			// The creation of the Secure Message's Payload serialized
			this.secureMessagePayloadSerialized = new byte[sizeOfSecureMessagePayloadSerialized];
			
			
			// Operations to Fill a Byte Array, with the following parameters:
			// 1) src - The source of the array to be copied
			// 2) srcPos - The position from the array to be copied, representing the first element to be copied
			// 3) dest - The destination of the array to be copied
			// 4) destPos - The position of the array where will be placed the new copy,
			//              representing the first element where new data will be placed
			// 5) length - The length of the data to be copied from the source array to the destination array
				
			// The offset related to fulfillment of the serialization process
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
			System.arraycopy(this.integrityControlHashedSerialized, 0, this.secureMessagePayloadSerialized, serializationOffset, this.integrityControlHashedSerialized.length);
			serializationOffset += this.integrityControlHashedSerialized.length;
			
			
			// The Secure Message's Payload have already its serialization undone
			this.isSecureMessagePayloadSerialized = false;
		}
	}
	
	/**
	 * Returns the Secure Message's Payload serialized.
	 * 
	 * @return the Secure Message's Payload serialized
	 */
	public byte[] getSecureMessagePayloadSerialized() {
		return this.isSecureMessagePayloadSerialized ? this.secureMessagePayloadSerialized : null;
	}
	
	/**
	 * Builds the Symmetric Encryption's Cipher on the Secure Message's Payload serialized,
	 * resulting to the final Secure Message's Payload component.
	 */
	public void buildSecureMessagePayloadSerializedSymmetricEncryptionCiphered() {
		
		// This process it's only made if the Integrity Control Hashed serialized of the Message
		// (i.e., the real content of the Message) of the Secure Message's Payload is done,
		// the Secure Message's Payload is serialized and its Symmetric Encryption Cipher it's not done
		if(this.isIntegrityControlHashedSerialized && this.isSecureMessagePayloadSerialized &&
		  !this.isSecureMessagePayloadSerializedSymmetricEncryptionCiphered) {
			
			byte[] secureMessagePayloadSerialized = this.getSecureMessagePayloadSerialized();
			
			try {
				
				// TODO - Retirar/Mudar depois
				// The byte stream input to generate a Secret Key
				// ( 4 x 8 = 32 bytes = 32 x 8 = 256 bits ),
				// because 1 byte is equal to 8 bits 
//				byte[] secretKeyBytes = new byte[] { 0x01, 0x23, 0x45, 0x67, (byte)0x89, (byte)0xab,(byte)0xcd, (byte)0xef, 
//													 0x01, 0x23, 0x45, 0x67, (byte)0x89, (byte)0xab,(byte)0xcd, (byte)0xef, 
//													 0x01, 0x23, 0x45, 0x67, (byte)0x89, (byte)0xab,(byte)0xcd, (byte)0xef,
//													 0x01, 0x23, 0x45, 0x67, (byte)0x89, (byte)0xab,(byte)0xcd, (byte)0xef };
				
				System.out.println("[SecureMessagePayload] Read ip: " + secureMessageAttributesParameters.getProperty("ip") +
						" and port as: " + secureMessageAttributesParameters.getProperty("port")
);
				
				byte[] secretKeyBytes = keystoreInterface.load(
						secureMessageAttributesParameters.getProperty("ip") 
						+ ":" +
						secureMessageAttributesParameters.getProperty("port")
						).getBytes();
				
				String symmetricEncryptionAlgorithm = this.secureMessageAttributesParameters.getProperty("sea");
		 	    String symmetricEncryptionMode = this.secureMessageAttributesParameters.getProperty("mode");
		 	    String symmetricEncryptionPadding = this.secureMessageAttributesParameters.getProperty("padding");
				
		        // Set the Secret Key and its specifications,
		 		// using the AES (Advanced Encryption Standard - Rijndael) Symmetric Encryption
		 	    SecretKeySpec secretKeySpecifications = new SecretKeySpec(secretKeyBytes, symmetricEncryptionAlgorithm);
		 	    
				
				Cipher secureMessagePayloadSerializationSymmetricEncryptionCipher = 
							Cipher.getInstance(String.format("%s/%s/%s",
											   symmetricEncryptionAlgorithm, symmetricEncryptionMode, symmetricEncryptionPadding), 
									           provider);

				if(requiresIV(symmetricEncryptionMode)) {
					// Algorithms that do not need IVs: ECB
					// The parameter specifications for the Initialization Vector				
					System.out.println("[SecureMessagePayload] Block mode needs IV");
					byte[] initialisingVectorBytes = new byte[] { 0x08, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 ,
				                         						   0x08, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 };
					IvParameterSpec initializationVectorParameterSpecifications = new IvParameterSpec(initialisingVectorBytes);
					secureMessagePayloadSerializationSymmetricEncryptionCipher
						.init(Cipher.ENCRYPT_MODE, secretKeySpecifications, initializationVectorParameterSpecifications);
				} else {
					System.out.println("[SecureMessagePayload] Block mode does not needs IV");
					secureMessagePayloadSerializationSymmetricEncryptionCipher
						.init(Cipher.ENCRYPT_MODE, secretKeySpecifications);
				}
								
				this.secureMessagePayloadSerializedSymmetricEncryptionCiphered = 
									secureMessagePayloadSerializationSymmetricEncryptionCipher.doFinal(secureMessagePayloadSerialized);
			
				
				// The Secure Message's Payload have already its serialization and its Symmetric Encryption Cipher done
				this.isSecureMessagePayloadSerializedSymmetricEncryptionCiphered = true;
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
	}
	
	/**
	 * Builds the Symmetric Encryption's Decipher on the Secure Message's Payload serialized,
	 * resulting to the Secure Message's Payload component.
	 */
	public void buildSecureMessagePayloadSerializationSymmetricEncryptionDeciphered() {
		
		// This process it's only made if the Integrity Control Hashed serialized of the Message
		// (i.e., the real content of the Message) of the Secure Message's Payload is done,
		// the Secure Message's Payload is serialized and its Symmetric Encryption Cipher it's done
		if(this.isIntegrityControlHashedSerialized && this.isSecureMessagePayloadSerialized &&
		   this.isSecureMessagePayloadSerializedSymmetricEncryptionCiphered) {
			
			try {
				// TODO - Retirar/Mudar depois
				// The byte stream input to generate a Secret Key
				// ( 4 x 8 = 32 bytes = 32 x 8 = 256 bits ),
				// because 1 byte is equal to 8 bits 
//				byte[] secretKeyBytes = new byte[] { 0x01, 0x23, 0x45, 0x67, (byte)0x89, (byte)0xab,(byte)0xcd, (byte)0xef, 
//													 0x01, 0x23, 0x45, 0x67, (byte)0x89, (byte)0xab,(byte)0xcd, (byte)0xef, 
//													 0x01, 0x23, 0x45, 0x67, (byte)0x89, (byte)0xab,(byte)0xcd, (byte)0xef ,
//													 0x01, 0x23, 0x45, 0x67, (byte)0x89, (byte)0xab,(byte)0xcd, (byte)0xef };	

				byte[] secretKeyBytes = keystoreInterface.load(
						secureMessageAttributesParameters.getProperty("ip") 
						+ ":" +
						secureMessageAttributesParameters.getProperty("port")
						).getBytes();
				
				String symmetricEncryptionAlgorithm = this.secureMessageAttributesParameters.getProperty("sea");
		 	    String symmetricEncryptionMode = this.secureMessageAttributesParameters.getProperty("mode");
		 	    String symmetricEncryptionPadding = this.secureMessageAttributesParameters.getProperty("padding");
				
		        // Set the Secret Key and its specifications,
		 		// using the AES (Advanced Encryption Standard - Rijndael) Symmetric Encryption
		 	    SecretKeySpec secretKeySpecifications = new SecretKeySpec(secretKeyBytes, symmetricEncryptionAlgorithm);

		 	    Cipher secureMessagePayloadSerializationSymmetricEncryptionDecipher = 
		 	    			Cipher.getInstance(String.format("%s/%s/%s",
										   	   symmetricEncryptionAlgorithm, symmetricEncryptionMode, symmetricEncryptionPadding), 
								               provider);
				
				if(requiresIV(symmetricEncryptionMode)) {
					// Algorithms that do not need IVs: ECB
					// The parameter specifications for the Initialization Vector	
					System.out.println("[SecureMessagePayload] Block mode needs IV");
					byte[] initialisingVectorBytes = new byte[] { 0x08, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 ,
				                         						   0x08, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 };
					IvParameterSpec initializationVectorParameterSpecifications = new IvParameterSpec(initialisingVectorBytes);
					secureMessagePayloadSerializationSymmetricEncryptionDecipher
						.init(Cipher.ENCRYPT_MODE, secretKeySpecifications, initializationVectorParameterSpecifications);
				} else {
					System.out.println("[SecureMessagePayload] Block mode does not needs IV");
					secureMessagePayloadSerializationSymmetricEncryptionDecipher
						.init(Cipher.ENCRYPT_MODE, secretKeySpecifications);
				}
				
				int sizeOfSecureMessagePayloadSerializedSymmetricEncryptionCiphered = 
									this.secureMessagePayloadSerializedSymmetricEncryptionCiphered.length;
				
		      	// The Plain Text of the bytes of the data input received through the communication channel
		      	this.secureMessagePayloadSerialized = new byte[secureMessagePayloadSerializationSymmetricEncryptionDecipher
		      	                                   .getOutputSize(sizeOfSecureMessagePayloadSerializedSymmetricEncryptionCiphered)];
		        
		      	int sizeOfSecureMessagePayloadSerialized = secureMessagePayloadSerializationSymmetricEncryptionDecipher
		      									   .update(this.secureMessagePayloadSerializedSymmetricEncryptionCiphered, 
		      											   0, sizeOfSecureMessagePayloadSerializedSymmetricEncryptionCiphered,
		      											   this.secureMessagePayloadSerialized, 0);
		      	
		      	secureMessagePayloadSerializationSymmetricEncryptionDecipher
		      									   .doFinal(this.secureMessagePayloadSerialized, sizeOfSecureMessagePayloadSerialized);
		        

				// The Secure Message's Payload have already its serialization and its Symmetric Encryption Cipher undone
				this.isSecureMessagePayloadSerializedSymmetricEncryptionCiphered = false;
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
			catch (ShortBufferException shortBufferException) {
				System.err.println("Error occurred during the Symmetric Encryption over the Secure Message's Payload:");
				System.err.println("- The Buffer in use, during the Deciphering process it's not correct!!!");
				shortBufferException.printStackTrace();
			}
		}
	}
	
	/**
	 * Returns the Symmetric Encryption's Cipher on the Secure Message's Payload serialized,
	 * resulting to the final Secure Message's Payload Ciphered component.
	 * 
	 * @return the Symmetric Encryption's Cipher on the Secure Message's Payload serialized,
	 *         resulting to the final Secure Message's Payload Ciphered component
	 */
	public byte[] SecureMessagePayloadSerializationSymmetricEncryptionCiphered() {
		return this.isSecureMessagePayloadSerializedSymmetricEncryptionCiphered ?
					this.secureMessagePayloadSerializedSymmetricEncryptionCiphered : null;
	}
	
	/**
	 * Used to check if a block mode needs an IV or not.
	 * The only block mode that does not need an IV is ECB.
	 * @param mode string of the block to compare to.
	 * @return true if it needs, false if not (ECB)
	 */
	private boolean requiresIV(String mode) {
		return !mode.equalsIgnoreCase("ECB");
	}
	
}