package multicast.sockets.messages.utils;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;

public class SecureMessageEncryptionHashingParameters {
	
	private String fullIPAddressAndPort;
	
	private String IPAddress;
	
	private String port;
	
	private String sessionID;
	
	private String symmetricEncryptionAlgorithm;
	
	private int symmetricEncryptionAlgorithmKeySize;
	
	private String symmetricEncryptionMode;
	
	private String paddingMethod;
	
	private String integrityControlCryptographicHashFunctionConstructionMethod;
	
	private String fastSecurePayloadCheckMessageAuthenticationCodeConstructionMethod;
	
	private int fastSecurePayloadCheckMessageAuthenticationCodeConstructionMethodKeySize;
	
	
	public SecureMessageEncryptionHashingParameters(String fullIPAddressAndPort) {
		this.fullIPAddressAndPort = fullIPAddressAndPort;
		
		String[] fullIPAddressAndPortParts = fullIPAddressAndPort.split(":");
		this.IPAddress = fullIPAddressAndPortParts[0];
		this.port = fullIPAddressAndPortParts[1];
	}
	
	private void getCiphersuiteConfigurationForSecureMulticastCommunicationProtocol() {
		File ciphersuiteConfigurationFile = null; // TODO
		
		try {
			BufferedReader bufferedReader = new BufferedReader(new FileReader(ciphersuiteConfigurationFile));
		
			
			boolean fullIPAddressAndPortFound = false;
			
			boolean sessionIDFound = false;
			
			boolean symmetricEncryptionAlgorithmFound = false;
			
			boolean symmetricEncryptionAlgorithmKeySizeFound = false;
			
			boolean symmetricEncryptionModeFound = false;
			
			boolean paddingMethodFound = false;
			
			boolean integrityControlCryptographicHashFunctionConstructionMethodFound = false;
			
			boolean fastSecurePayloadCheckMessageAuthenticationCodeConstructionMethodFound = false;
			
			boolean fastSecurePayloadCheckMessageAuthenticationCodeConstructionMethodKeySizeFound = false;
			
			
			String auxiliarStringReader = "";
			
			while( ((auxiliarStringReader = bufferedReader.readLine()) != null) && !fullIPAddressAndPortFound) {
				
				if(auxiliarStringReader.equalsIgnoreCase("<" + fullIPAddressAndPort + ">")) {
					fullIPAddressAndPortFound = true;
					
					while( ((auxiliarStringReader = bufferedReader.readLine()) != null) && 
							(!sessionIDFound || !symmetricEncryptionAlgorithmFound || !symmetricEncryptionAlgorithmKeySizeFound || 
							 !symmetricEncryptionModeFound || !paddingMethodFound || !integrityControlCryptographicHashFunctionConstructionMethodFound ||
							 !fastSecurePayloadCheckMessageAuthenticationCodeConstructionMethodFound || 
							 !fastSecurePayloadCheckMessageAuthenticationCodeConstructionMethodKeySizeFound) ) {
						
						if( (auxiliarStringReader.contains("<SESSION-ID>")) && (auxiliarStringReader.contains("</SESSION-ID>")) ) {
							this.sessionID = auxiliarStringReader.split("<SESSION-ID>")[1].split("</SESSION-ID>")[0];
							
							sessionIDFound = true;
						}
						
						if( (auxiliarStringReader.contains("<SYMMETRIC-ENCRYPTION-ALGORITHM>")) && 
							(auxiliarStringReader.contains("</SYMMETRIC-ENCRYPTION-ALGORITHM>")) ) {
							
							this.symmetricEncryptionAlgorithm = auxiliarStringReader.split("<SYMMETRIC-ENCRYPTION-ALGORITHM>")[1]
																					.split("</SYMMETRIC-ENCRYPTION-ALGORITHM>")[0];
							
							symmetricEncryptionAlgorithmFound = true;
						}
						
						if( (auxiliarStringReader.contains("<SYMMETRIC-ENCRYPTION-ALGORITHM-KEY-SIZE>")) && 
							(auxiliarStringReader.contains("</SYMMETRIC-ENCRYPTION-ALGORITHM-KEY-SIZE>")) ) {
							
							String symmetricEncryptionAlgorithmKeySizeString = auxiliarStringReader.split("<SYMMETRIC-ENCRYPTION-ALGORITHM-KEY-SIZE>")[1]
																						           .split("</SYMMETRIC-ENCRYPTION-ALGORITHM-KEY-SIZE>")[0];
							
							this.symmetricEncryptionAlgorithmKeySize = Integer.parseInt(symmetricEncryptionAlgorithmKeySizeString);
							
							symmetricEncryptionAlgorithmKeySizeFound = true;
						}
						
						if( (auxiliarStringReader.contains("<SYMMETRIC-ENCRYPTION-MODE>")) &&
							(auxiliarStringReader.contains("</SYMMETRIC-ENCRYPTION-MODE>")) ) {
							
							this.symmetricEncryptionMode = auxiliarStringReader.split("<SYMMETRIC-ENCRYPTION-MODE>")[1]
														   					   .split("</SYMMETRIC-ENCRYPTION-MODE>")[0];
							
							symmetricEncryptionModeFound = true;
						}
						
						if( (auxiliarStringReader.contains("<PADDING-METHOD>")) &&
							(auxiliarStringReader.contains("</PADDING-METHOD>")) ) {
							
							this.paddingMethod = auxiliarStringReader.split("<PADDING-METHOD>")[1]
												  					 .split("</PADDING-METHOD>")[0];
							
							paddingMethodFound = true;
						}
						
						if( (auxiliarStringReader.contains("<INTEGRITY-CONTROL-CRYPTOGRAPHIC-HASH-FUNCTION-CONSTRUCTION-METHOD>")) &&
							(auxiliarStringReader.contains("</INTEGRITY-CONTROL-CRYPTOGRAPHIC-HASH-FUNCTION-CONSTRUCTION-METHOD>")) ) {
							
							this.integrityControlCryptographicHashFunctionConstructionMethod = 
																auxiliarStringReader.split("<INTEGRITY-CONTROL-CRYPTOGRAPHIC-HASH-FUNCTION-CONSTRUCTION-METHOD>")[1]
																					.split("</INTEGRITY-CONTROL-CRYPTOGRAPHIC-HASH-FUNCTION-CONSTRUCTION-METHOD>")[0];
							
							integrityControlCryptographicHashFunctionConstructionMethodFound = true;
						}
						
						if( (auxiliarStringReader.contains("<FAST-SECURE-PAYLOAD-CHECK-MESSAGE-AUTHENTICATION-CODE-CONSTRUCTION-METHOD>")) &&
							(auxiliarStringReader.contains("</FAST-SECURE-PAYLOAD-CHECK-MESSAGE-AUTHENTICATION-CODE-CONSTRUCTION-METHOD>")) ) {
							
							this.fastSecurePayloadCheckMessageAuthenticationCodeConstructionMethod = 
																auxiliarStringReader.split("<FAST-SECURE-PAYLOAD-CHECK-MESSAGE-AUTHENTICATION-CODE-CONSTRUCTION-METHOD>")[1]
																					.split("</FAST-SECURE-PAYLOAD-CHECK-MESSAGE-AUTHENTICATION-CODE-CONSTRUCTION-METHOD>")[0];
							
							fastSecurePayloadCheckMessageAuthenticationCodeConstructionMethodFound = true;
						}
						
						if( (auxiliarStringReader.contains("<FAST-SECURE-PAYLOAD-CHECK-MESSAGE-AUTHENTICATION-CODE-CONSTRUCTION-METHOD-KEY-SIZE>")) &&
							(auxiliarStringReader.contains("</FAST-SECURE-PAYLOAD-CHECK-MESSAGE-AUTHENTICATION-CODE-CONSTRUCTION-METHOD-KEY-SIZE>")) ) {
							
							String fastSecurePayloadCheckMessageAuthenticationCodeConstructionMethodKeySizeString = 
																auxiliarStringReader.split("<FAST-SECURE-PAYLOAD-CHECK-MESSAGE-AUTHENTICATION-CODE-CONSTRUCTION-METHOD-KEY-SIZE>")[1]
																					.split("</FAST-SECURE-PAYLOAD-CHECK-MESSAGE-AUTHENTICATION-CODE-CONSTRUCTION-METHOD-KEY-SIZE>")[0];
							
							this.fastSecurePayloadCheckMessageAuthenticationCodeConstructionMethodKeySize = Integer.parseInt(fastSecurePayloadCheckMessageAuthenticationCodeConstructionMethodKeySizeString);
							
							fastSecurePayloadCheckMessageAuthenticationCodeConstructionMethodKeySizeFound = true;
						}
						
						if(auxiliarStringReader.equalsIgnoreCase("<" + fullIPAddressAndPort + ">")) {
							break;
						}
					}
				}
			}
		}
		catch (FileNotFoundException fileNotFoundException) {
			System.err.println("The Ciphersuite Configuration File isn't on the expected location!!!");
			fileNotFoundException.printStackTrace();
		}
		catch (IOException inputOutputException) {
			System.err.println("Error occured during the reading of the Ciphersuite Configuration File!!!");
			inputOutputException.printStackTrace();
		}
	}
}