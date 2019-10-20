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

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import javax.crypto.Mac;
import multicast.common.CommonUtils;
import multicast.sockets.messages.utils.SecureMulticastChatSessionParameters;

/**
 * 
 * Class for the Fast Secure Message's Check.
 * 
 * @supervisor Prof. Henrique Joao Domingos - hj@fct.unl.pt
 * 
 * @author Eduardo Bras Silva (no. 41798) - emf.silva@campus.fct.unl.pt
 * @author Ruben Andre Barreiro (no. 42648) - r.barreiro@campus.fct.unl.pt
 *
 */
public class FastSecureMessageCheck {
	
	// Global Instance Variables:
	/**
	 * The Secure Message serialized
	 */
	private byte[] secureMessageSerialized;
	
	/**
	 * The Secure Message serialized hashed
	 */
	private byte[] secureMessageSerializedHashed;
	
	/**
	 * The boolean to keep the value to check if
	 * the Secure Message serialized is hashed
	 */
	private boolean isSecureMessageSerializedHashed;
	
	/**
	 * Properties Reader from file
	 */
	private SecureMulticastChatSessionParameters propertiesReader;
	
	/**
	 * Filename of Properties' file
	 */
	private static final String propertiesFilename = "./res/SMCP.conf";
	
	
	
	// Constructors:
	/**
	 * Constructor #1:
	 * - The Constructor of the Fast Secure Message's Check,
	 *   performing/computing the hash on the Secure Message serialized.
	 * 
	 * @param secureMessageSerialized the Secure Message serialized
	 */
	public FastSecureMessageCheck(byte[] secureMessageSerialized) {
		this.secureMessageSerialized = secureMessageSerialized;
		
		this.isSecureMessageSerializedHashed = false;
		
		this.propertiesReader = new SecureMulticastChatSessionParameters(propertiesFilename);
	}
	
	/**
	 * Constructor #2:
	 * - The Constructor of the Fast Secure Message's Check,
	 *   comparing the hash of the received Secure Message serialized with
	 *   the received Secure Message serialized hashed.
	 * 
	 * @param secureMessageSerialized the Secure Message serialized
	 * 
	 * @param secureMessageSerializedHashed the Secure Message serialized hashed
	 */
	public FastSecureMessageCheck(byte[] secureMessageSerialized, byte[] secureMessageSerializedHashed) {
		this.secureMessageSerialized = secureMessageSerialized;
		this.secureMessageSerializedHashed = secureMessageSerializedHashed;
		
		this.isSecureMessageSerializedHashed = true;
		
		this.propertiesReader = new SecureMulticastChatSessionParameters(propertiesFilename);
	}
	
	
	
	// Methods:
	/**
	 * Returns the Secure Message serialized.
	 * 
	 * @return the Secure Message serialized
	 */
	public byte[] getSecureMessageSerialized() {
		return isSecureMessageSerializedHashed ? this.secureMessageSerialized : null;
	}
	
	/**
	 * Returns the Secure Message serialized hashed.
	 * 
	 * @return the Secure Message serialized hashed
	 */
	public byte[] getSecureMessageSerializedHashed() {
		return this.isSecureMessageSerializedHashed ? this.secureMessageSerializedHashed : null;
	}
	
	/**
	 * Builds the Secure Message serialized hashed.
	 */
	public void buildSecureMessageSerializedHashed() {
		
		System.out.println("VOU FAZER O FAST HASH");
		System.out.println("TAMANHO DO MESSAGE");
		System.out.println(secureMessageSerialized.length);
		
		if(!this.isSecureMessageSerializedHashed) {
			
			// Starts the MAC Hash process over the Secure Message serialized (applying the HMAC or CMAC operation),
			// before the sending of the final concatenation of it with Secure Message serialized
			try {
			
				// The Source/Seed of a Secure Random
				SecureRandom secureRandom = new SecureRandom();
				
				// The Initialization Vector and its Parameter's Specifications
				Key secureMessageSerializedMACKey = CommonUtils
						.createKeyForAES(Integer.parseInt(this.propertiesReader.getProperty("macks")),
									     secureRandom);
				
				// The configuration, initialization and update of the MAC Hash process
				Mac mac = Mac.getInstance(this.propertiesReader.getProperty("mac"));
				mac.init(secureMessageSerializedMACKey);
				mac.update(this.secureMessageSerialized);
				
				// Performs the final operation of MAC Hash process over the Secure Message serialized
				// (applying the HMAC or CMAC operation)
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
	
	/**
	 * Returns true if the hash performed/computed over Secure Message serialized received its valid,
	 * comparing it with the Secure Message serialized hashed received and false, otherwise.
	 * 
	 * @return true if the hash performed/computed over Secure Message serialized received its valid,
	 * 		   comparing it with the Secure Message serialized hashed received and false, otherwise
	 */
	public boolean checkIfIsSecureMessageSerializedHashedValid() {
		
		// TODO
		if(this.isSecureMessageSerializedHashed) {
			System.out.println("VAI VERIFICAR O HASH");
			
			// TODO
			byte[] secureMessageSerializedHashedToCompare = this.secureMessageSerialized;
			
			// Starts the MAC Hash process over the Secure Message serialized received (applying the HMAC or CMAC operation),
			// comparing it with Secure Message serialized hashed received (the MAC Hash process related to the Fast Secure Message Check)
			try {
			
				// The Source/Seed of a Secure Random
				SecureRandom secureRandom = new SecureRandom();
				
				// The Initialization Vector and its Parameter's Specifications
				Key secureMessageSerializedMACKey = CommonUtils
						.createKeyForAES(Integer.parseInt(this.propertiesReader.getProperty("macks")),
								         secureRandom);
				
				// The configuration, initialization and update of the MAC Hash process
				Mac mac = Mac.getInstance(this.propertiesReader.getProperty("mac"));
				mac.init(secureMessageSerializedMACKey);
				mac.update(secureMessageSerializedHashedToCompare);
				
				// Performs the final operation of MAC Hash process over the Secure Message serialized
				// (applying the HMAC or CMAC operation)
				secureMessageSerializedHashedToCompare = mac.doFinal();
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

			System.out.println();
			System.out.println();
			System.out.println("TAMANHO DOS HASHES:");
			System.out.println(secureMessageSerializedHashedToCompare.length);
			System.out.println(secureMessageSerializedHashed.length);
			System.out.println();
			System.out.println();

			System.out.println("CONTEUDO DOS HASHES:");
			System.out.println(CommonUtils.fromByteArrayToHexadecimalFormat(secureMessageSerializedHashedToCompare));
			System.out.println(CommonUtils.fromByteArrayToHexadecimalFormat(secureMessageSerializedHashed));
			
			// Returns true if the hash performed/computed over Secure Message serialized received its valid,
			// comparing it with the Secure Message serialized hashed received and false, otherwise
			return (this.isSecureMessageSerializedHashed &&
					this.secureMessageSerializedHashed.equals(secureMessageSerializedHashedToCompare)) ? 
							true : false;	
		}
		
		return false;
	}
}