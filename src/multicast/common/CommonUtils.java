package multicast.common;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class CommonUtils {
	
	// Invariants/Constants:
	
	/**
	 * The current version of the Secure Messages' Protocol
	 */
	public static final byte CURRENT_VERSION_PROTOCOL = VersionNumber.VERSION_00.getVersionNumber();
	
	/**
	 * The Number of Components, contained in the Meta Header
	 */
	public static final int NUM_COMPONENTS_META_HEADER = 4;
	
	/**
	 * The Total Number of Outside Separators, contained in the Meta Header
	 */
	public static final int META_HEADER_OUTSIDE_SEPARATORS = 2;
	
	/**
	 * The Total Length of an Outside Separator, contained in the Meta Header
	 */
	public static final int META_HEADER_OUTSIDE_SEPARATORS_LENGTH = 2;
	
	/**
	 * The Total Number of Inside Separators, contained in the Meta Header
	 */
	public static final int META_HEADER_INSIDE_SEPARATORS = 3;
	
	/**
	 * The Total Length of an Inside Separator, contained in the Meta Header
	 */
	public static final int META_HEADER_INSIDE_SEPARATORS_LENGTH = 1;
	
	/**
	 * The Total Length of a Byte
	 */
	public static final int BYTE_LENGTH = 1;
	
	/**
	 * The Total Length of a Char
	 */
	public static final int CHAR_LENGTH = 1;

	/**
	 * The Total Length of a Short
	 */
	public static final int SHORT_LENGTH = 2;
	
	/**
	 * The Total Length of an Integer
	 */
	public static final int INTEGER_LENGTH = 4;
	
	/**
	 * The Total Length of a Long
	 */
	public static final int LONG_LENGTH = 6;
	
	/**
	 * The ID of the JOIN Message
	 */
	public static final byte JOIN_MESSAGE = ((byte) 1);

	/**
	 * The ID of the LEAVE Message
	 */
	public static final byte LEAVE_MESSAGE = ((byte) 2);

	/**
	 * The ID of the TEXT Message
	 */
	public static final byte TEXT_MESSAGE = ((byte) 3);
	
	/**
	 * The Rate Time for verification of the Cleaning Random Nonces Service
	 */
	public static final long CLEANING_RANDOM_NONCES_SERVICE_VERIFICATION_RATE_TIME = 10000;
	
	/**
	 * The Timeout for triggering the event of Cleaning/Removing old Random Nonces
	 */
	public static final long RANDOM_NONCES_CLEANING_TIMEOUT = 600000;
	
	
	
	// Global Instance Variables:
	/**
	 * The digits of the Byte Array of data, in hexadecimal
	 */
    private static String digits = "0123456789abcdef";
	
    
    
    // Methods/Functions:
    /**
     * Returns and converts a Byte, from a given Character.
     * 
     * @param charCharacter a given Character to be converted
     * 
     * @return and converts a Byte, from a given Character
     */
	public static byte fromCharToByte(char charCharacter) {
		return ( (byte) charCharacter );
	}

	/**
     * Returns and converts a Byte Array, from a given Short Number.
     * 
     * @param shortNumber a given Short Number to be converted
     * 
     * @return and converts a Byte Array, from a given Short Number
     */
	public static byte[] fromShortToByteArray(short shortNumber) {
		byte[] shortNumberSerialized = new byte[SHORT_LENGTH];
		
		ByteBuffer byteBuffer = ByteBuffer.wrap(shortNumberSerialized);
		byteBuffer.order(ByteOrder.nativeOrder()).putShort(shortNumber);
		
		return shortNumberSerialized;
	}
	
	/**
     * Returns and converts a Byte Array, from a given Integer Number.
     * 
     * @param integerNumber a given Integer Number to be converted
     * 
     * @return and converts a Byte Array, from a given Integer Number
     */
	public static byte[] fromIntToByteArray(int integerNumber) {
		byte[] integerNumberSerialized = new byte[INTEGER_LENGTH];
		
		ByteBuffer byteBuffer = ByteBuffer.wrap(integerNumberSerialized);
		byteBuffer.order(ByteOrder.nativeOrder()).putInt(integerNumber);
		
		return integerNumberSerialized;
	}
	
	/**
     * Returns and converts a Byte Array, from a given Long Number.
     * 
     * @param longNumber a given Long Number to be converted
     * 
     * @return and converts a Byte Array, from a given Long Number
     */
	public static byte[] fromLongToByteArray(long longNumber) {
		byte[] longNumberSerialized = new byte[LONG_LENGTH];
		
		ByteBuffer byteBuffer = ByteBuffer.wrap(longNumberSerialized);
		byteBuffer.order(ByteOrder.nativeOrder()).putLong(longNumber);
		
		return longNumberSerialized;
	}
	
	/**
     * Returns and converts a Byte Array, from a given String.
     * 
     * @param string a given String to be converted
     * 
     * @return and converts a Byte Array, from a given String
     */
    public static byte[] fromStringToByteArray(String string) {
        byte[] bytes = new byte[string.length()];
        char[] chars = string.toCharArray();
        
        for (int i = 0; i != chars.length; i++) {
            bytes[i] = (byte) chars[i];
        }
        
        return bytes;
    }
	
    /**
     * Returns and converts a Char, from a given Byte.
     * 
     * @param charCharacterByte a given Byte to be converted
     * 
     * @return and converts a Char, from a given Byte
     */
    public static char fromByteToChar(byte charCharacterByte) {
		return ( (char) ( charCharacterByte & 0xff ) );
	}
	
    /**
     * Returns and converts a Short Number, from a given Byte Array.
     * 
     * @param shortNumberByteArray a given Byte Array to be converted
     * 
     * @return and converts a Short Number, from a given Byte Array
     */
	public static short fromByteArrayToShort(byte[] shortNumberByteArray) {
		ByteBuffer byteBuffer = ByteBuffer.wrap(shortNumberByteArray);
		short shortNumberDeserialized = byteBuffer.order(ByteOrder.nativeOrder()).getShort();
		
		return shortNumberDeserialized;
	}
	
	/**
     * Returns and converts an Integer Number, from a given Byte Array.
     * 
     * @param integerNumberByteArray a given Byte Array to be converted
     * 
     * @return and converts an Integer Number, from a given Byte Array
     */
	public static int fromByteArrayToInt(byte[] integerNumberByteArray) {
		ByteBuffer byteBuffer = ByteBuffer.wrap(integerNumberByteArray);
		int integerNumberDeserialized = byteBuffer.order(ByteOrder.nativeOrder()).getInt();
		
		return integerNumberDeserialized;
	}
	
	/**
     * Returns and converts a Long Number, from a given Byte Array.
     * 
     * @param longNumberByteArray a given Byte Array to be converted
     * 
     * @return and converts a Long Number, from a given Byte Array
     */
	public static long fromByteArrayToLong(byte[] longNumberByteArray) {
		ByteBuffer byteBuffer = ByteBuffer.wrap(longNumberByteArray);
		long longNumberDeserialized = byteBuffer.order(ByteOrder.nativeOrder()).getLong();
		
		return longNumberDeserialized;
	}
	
    /**
     * Returns and converts a String, from a Byte Array of characters,
     * but given a Number of Bytes to be converted, which can't be
     * the Total Length of the Byte Array.
     * 
     * @param bytes the Byte Array to be converted
     * @param length the total Size/Length or Number of Bytes to be converted
     * 
     * @return and converts a String, from a Byte Array of characters,
     * 		   but given a Number of Bytes to be converted, which can't be
     *         the Total Length of the Byte Array
     */
    public static String fromByteArrayToString(byte[] bytes, int length) {
        char[] chars = new char[length];
        
        for (int i = 0; i != chars.length; i++) {
            chars[i] = (char)(bytes[i] & 0xff);
        }
        
        return new String(chars);
    }
    
    /**
     * Returns and converts a String, from a Byte Array of characters.
     * 
     * @param bytes the Byte Array to be converted
     * 
     * @return and converts a String, from a Byte Array of Characters
     */
    public static String fromByteArrayToString(byte[] bytes) {
        return fromByteArrayToString(bytes, bytes.length);
    }
	
	/**
     * Returns the given Byte Array of data, in a hexadecimal format, given also, the original length.
     * 
     * @param data the Byte Array of data
     * @param length the length of the Byte Array of bytes
     * 
     * @return the given Byte Array of data, in a hexadecimal format, given also, the original length
     */
     public static String fromByteArrayToHexadecimalFormat(byte[] data, int length) {
        StringBuffer stringBuffer = new StringBuffer();
        
        for (int i = 0; i != length; i++) {
            int	vector = data[i] & 0xff;
            
            stringBuffer.append(digits.charAt(vector >> 4));
            stringBuffer.append(digits.charAt(vector & 0xf));
        }
        
        return stringBuffer.toString();
     }
     
     /**
      * Returns the given Byte Array of data, in a hexadecimal format.
      * 
      * @param data the Byte Array of data
      * 
      * @return the given Byte Array of data, in a hexadecimal format
      */
      public static String fromByteArrayToHexadecimalFormat(byte[] data) {
          return fromByteArrayToHexadecimalFormat(data, data.length);
      }
      
      /**
	   * Returns a created Secret Key, using the AES (Advanced Encryption Standard - Rijndael)
	   * Encryption Algorithm
	   * 
	   * @param keyBitSize the size/length pretended for the Secret Key
	   * @param secureRandom the source/seed for a secure random
	   * 
	   * @return a created Secret Key, using the AES (Advanced Encryption Standard - Rijndael)
	   *  		 Encryption Algorithm
	   * 
	   * @throws NoSuchAlgorithmException a NoSuchAlgortihmException to be thrown, in the case of,
	   * 		                          the Secure/Cryptographic Algorithm pretended to be used,
	   *                                  don't exist or it's not installed
	   * @throws NoSuchProviderException a NoSuchProviderException to be thrown, in the case of,
	   * 		                         the Secure/Cryptographic Provider pretended to be used,
	   *                                 don't exist or it's not installed
	   */
      public static SecretKey createKeyForAES(int keyBitSize, SecureRandom secureRandom)
      			throws NoSuchAlgorithmException, NoSuchProviderException {
      	
          KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
          
          // Initialize the Key Generator with a given bit size/length
          // NOTE:
          // - In this case, it will be used a Secret Key with 256-bits of size
          keyGenerator.init(256, secureRandom);
          //keyGenerator.init(keyBitSize, secureRandom);
          
          return keyGenerator.generateKey();
      }
      
      /**
       * Returns a created Initialization Vector and its Parameter Specifications
       * to use in a Cipher's Suite, which use AES (Advanced Encryption Standard - Rijndael)
       * Encryption Algorithm
       * 
       * NOTE:
       * - The Initialization Vector composed by 4 bytes (message number),
       *   4 random bytes and a counter of 8 bytes;
       * 
       * @param messageNumber the message number
       * @param secureRandom a source/seed for a secure random
       * 
       * @return a created Initialization Vector and its Parameter Specifications
       * 		 to use in a Cipher's Suite, which use AES (Advanced Encryption Standard - Rijndael)
       *         Encryption Algorithm
       */
      public static IvParameterSpec createCtrIvForAES(int messageNumber, SecureRandom secureRandom) {
      	  byte[] initializationVectorBytes = new byte[16];
          
          // Initially randomize   
          secureRandom.nextBytes(initializationVectorBytes);
          
          // Set the message number bytes
          initializationVectorBytes[0] = (byte) (messageNumber >> 24);
          initializationVectorBytes[1] = (byte) (messageNumber >> 16);
          initializationVectorBytes[2] = (byte) (messageNumber >> 8);
          initializationVectorBytes[3] = (byte) (messageNumber >> 0);
          
          // Set the counter bytes to 1
          for (int i = 0; i != 7; i++) {
          	initializationVectorBytes[(8 + i)] = 0;
          }
          
          initializationVectorBytes[15] = 1;
          
          return new IvParameterSpec(initializationVectorBytes);
      }
}