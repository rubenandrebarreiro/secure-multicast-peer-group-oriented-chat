package multicast.common;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class CommonUtils {
	
	public static final int NUM_COMPONENTS_META_HEADER = 4;
	
	public static final int BYTE_LENGTH = 4;
	public static final int CHAR_LENGTH = 1;
	public static final int SHORT_LENGTH = 2;
	public static final int INTEGER_LENGTH = 4;
	public static final int LONG_LENGTH = 6;
	
	public static final int META_HEADER_OUTSIDE_SEPARATORS = 2;
	public static final int META_HEADER_OUTSIDE_SEPARATORS_LENGTH = 2;
	
	
	public static final int META_HEADER_INSIDE_SEPARATORS = 3;
	public static final int META_HEADER_INSIDE_SEPARATORS_LENGTH = 1;
	
	
	public static byte[] fromIntToByteArray(int integerNumber) {
		byte[] integerNumberSerialized = new byte[INTEGER_LENGTH];
		
		ByteBuffer byteBuffer = ByteBuffer.wrap(integerNumberSerialized);
		byteBuffer.order(ByteOrder.nativeOrder()).putInt(integerNumber);
		
		return integerNumberSerialized;
	}
	
	public static byte[] fromStringToByteArray(String stringPhrase) {		
		return stringPhrase.getBytes();
	}
}