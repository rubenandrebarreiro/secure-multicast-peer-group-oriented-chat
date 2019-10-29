package multicast.sockets.messages.components;

import java.util.ArrayList;
import java.util.List;

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

import multicast.common.CommonUtils;
import multicast.common.MessageType;
import multicast.common.VersionNumber;

/**
 * 
 * Class for the Secure Message's Header.
 * 
 * @supervisor Prof. Henrique Joao Domingos - hj@fct.unl.pt
 * 
 * @author Eduardo Bras Silva (no. 41798) - emf.silva@campus.fct.unl.pt
 * @author Ruben Andre Barreiro (no. 42648) - r.barreiro@campus.fct.unl.pt
 *
 */
public class SecureMessageHeader {
	
	// Global Instance Variables:
	/**
	 * The Version's Number of the Secure Message's Protocol
	 */
	private byte versionNumber;
	
	/**
	 * The Session's ID, using the Secure Message's Protocol
	 */
	private String sessionID;
	
	/**
	 * The Message's Type, using the Secure Message's Protocol
	 */
	private byte messageType;
	
	/**
	 * The byte array of the Secure Message's Header serialized
	 */
	private byte[] secureMessageHeaderSerialized;
	
	/**
	 * The boolean to keep the value to check if
	 * the Secure Message's Header is serialized
	 */
	private boolean isSecureMessageHeaderSerialized;
	
	
	
	// Constructors:
	/**
	 * Constructor #1:
	 * - The Constructor of the Secure Message's Header,
	 *   with the respectively components of it.
	 * 
	 * @param versionNumber the Version's Number of the Secure Message's Protocol
	 * 
	 * @param sessionID the Session's ID, using the Secure Message's Protocol
	 * 
	 * @param messageType the Message's Type, using the Secure Message's Protocol
	 */
	public SecureMessageHeader(byte versionNumber, String sessionID, byte messageType) {
		this.versionNumber = versionNumber;
		this.sessionID = sessionID;
		this.messageType = messageType;
		
		this.isSecureMessageHeaderSerialized = false;
	}
	
	/**
	 * Constructor #2;
	 * - The Constructor of the Secure Message's Header,
	 *   from the concatenation of the respectively serialized components of the Secure Message's Header.
	 * 
	 * @param secureMessageHeaderSerialized the concatenation of the respectively serialized components of
	 *        the Secure Message's Header
	 */
	public SecureMessageHeader(byte[] secureMessageHeaderSerialized) {
		this.secureMessageHeaderSerialized = secureMessageHeaderSerialized;
		
		this.isSecureMessageHeaderSerialized = true;
	}
	
	
	
	// Methods/Functions:
	/**
	 * Returns the Version's Number of the Secure Message's Protocol.
	 * 
	 * @return the Version's Number of the Secure Message's Protocol
	 */
	public byte getVersionNumber() {
		return this.isSecureMessageHeaderSerialized ? null : this.versionNumber;
	}
	 
	/**
	 * Returns the Session's ID, using the Secure Message's Protocol.
	 * 
	 * @return the Session's ID, using the Secure Message's Protocol
	 */
	public String getSessionID() {
		return this.isSecureMessageHeaderSerialized ? null : this.sessionID;
	}
	
	/**
	 * Returns the Message's Type, using the Secure Message's Protocol.
	 * 
	 * @return the Message's Type, using the Secure Message's Protocol
	 */
	public byte getMessageType() {
		return this.isSecureMessageHeaderSerialized ? null : this.messageType;
	}

	/**
	 * Builds the Secure Message's Header serialized.
	 */
	public void buildMessageHeaderSerialized() {
				
		// This process it's only made if the Secure Message's Header is not serialized
		if(!this.isSecureMessageHeaderSerialized) {
			
			// The Version's Number of the Secure Message's Protocol
			byte[] versionNumberSerialized = new byte[CommonUtils.BYTE_LENGTH];
			versionNumberSerialized[0] = this.versionNumber;
			
			// The Session's ID serialized, using the Secure Message's Protocol
			byte[] sessionIDSerialized = CommonUtils.fromStringToByteArray(this.getSessionID());
			
			// The Message's Type, using the Secure Message's Protocol
			byte[] messageTypeSerialized = new byte[CommonUtils.BYTE_LENGTH];
			messageTypeSerialized[0] = this.messageType;
			
			
			// The size of the Secure Message's Header serialized
			int sizeOfMessageHeaderSerialized = ( sessionIDSerialized.length + ( 2 * CommonUtils.BYTE_LENGTH ) );
			
			// The creation of the Secure Message's Header serialized
			this.secureMessageHeaderSerialized = new byte[sizeOfMessageHeaderSerialized];
						
			// Operations to Fill a Byte Array, with the following parameters:
			// 1) src - The source of the array to be copied
			// 2) srcPos - The position from the array to be copied, representing the first element to be copied
			// 3) dest - The destination of the array to be copied
			// 4) destPos - The position of the array where will be placed the new copy,
			//              representing the first element where new data will be placed
			// 5) length - The length of the data to be copied from the source array to the destination array
			
			// The offset related to fulfillment of the serialization process
			int serializationOffset = 0;

			// Fills the byte array of the Secure Message Header with the serialization of the Version's Number,
			// From the position corresponding to the length of the byte of the Version's Number
			System.arraycopy(versionNumberSerialized, 0, this.secureMessageHeaderSerialized, 0, CommonUtils.BYTE_LENGTH);
			serializationOffset += CommonUtils.BYTE_LENGTH;
						
			// Fills the byte array of the Secure Message Header with the serialization of the Session's ID,
			// From the position corresponding to the length of the byte array of the Session's ID
			System.arraycopy(sessionIDSerialized, 0, this.secureMessageHeaderSerialized, serializationOffset, sessionIDSerialized.length);
			serializationOffset += sessionIDSerialized.length;
			
			// Fills the byte array of the Secure Message Header with the serialization of the Message's Type,
			// From the position corresponding to the length of the byte of the Message's Type
			System.arraycopy(messageTypeSerialized, 0, this.secureMessageHeaderSerialized, serializationOffset, CommonUtils.BYTE_LENGTH);
			serializationOffset += CommonUtils.BYTE_LENGTH;
			
			// The Secure Message's Header have already its serialization done
			this.isSecureMessageHeaderSerialized = true;
		}	
	}
	
	/**
	 * Builds the several parts of the Secure Message's Header from
	 * the Secure Message's Header serialized.
	 */
	public void buildSecureMessageHeaderComponents() {
		
		// This process it's only made if the Secure Message's Header is serialized
		if(this.isSecureMessageHeaderSerialized) {
			
			// The Version's Number of the Secure Message's Protocol			
			this.versionNumber = this.secureMessageHeaderSerialized[0];

			// The Session's ID serialized, using the Secure Message's Protocol
			byte[] sessionIDSerialized = new byte[ (secureMessageHeaderSerialized.length - ( 2 * CommonUtils.BYTE_LENGTH ) ) ];
			
			// Fills the byte array of the Session's ID, using the Secure Message's Protocol from
			// the byte array of the Secure Message Header serialized
			System.arraycopy(secureMessageHeaderSerialized, CommonUtils.BYTE_LENGTH,
							 sessionIDSerialized, 0, ( secureMessageHeaderSerialized.length - CommonUtils.BYTE_LENGTH ));

			// The Session's ID, using the Secure Message's Protocol
			this.sessionID = CommonUtils.fromByteArrayToString(sessionIDSerialized);
			
			// The Message's Type, using the Secure Message's Protocol
			this.messageType = secureMessageHeaderSerialized[ ( secureMessageHeaderSerialized.length - CommonUtils.BYTE_LENGTH ) ];
			
			// The Secure Message's Header have already its serialization undone
			this.isSecureMessageHeaderSerialized = false;
		}
	}
	
	/**
	 * Returns the Secure Message's Header serialized.
	 * 
	 * @return the Secure Message's Header serialized
	 */
	public byte[] getSecureMessageHeaderSerialized() {
		return this.isSecureMessageHeaderSerialized ? this.secureMessageHeaderSerialized : null;
	}
	
	/**
	 * TODO
	 * @return
	 */
	public boolean isVersionNumberSupported() {
		if(!this.isSecureMessageHeaderSerialized) {
			List<Byte> versionNumbersProtocolList = new ArrayList<Byte>();
			
			for(VersionNumber versionNumberProtocolAvailable : VersionNumber.values()) {
				versionNumbersProtocolList.add(versionNumberProtocolAvailable.getVersionNumber());
			}
			
			return versionNumbersProtocolList.contains(this.versionNumber);
		}
		
		return false;
	}
	
	/**
	 * TODO
	 * @return
	 */
	public boolean isMessageTypeSupported() {
		if(!this.isSecureMessageHeaderSerialized) {
			List<Byte> messageTypeProtocolList = new ArrayList<Byte>();
			
			for(MessageType messageTypeProtocolAvailable : MessageType.values()) {
				messageTypeProtocolList.add(messageTypeProtocolAvailable.getMessageType());
			}
			
			return messageTypeProtocolList.contains(this.messageType);
		}
		
		return false;
	}
	
	
	public boolean isVersionNumberAndMessageTypeSupported() {
		if(!this.isSecureMessageHeaderSerialized) {
			boolean isVersionNumberSupported = this.isVersionNumberSupported();
			boolean isMessageTypeSupported = this.isMessageTypeSupported();
			
			if(!isVersionNumberSupported) {
				System.err.println("The Version Number of the Secure Message Protocol it's not supported!!!");
				
				return false;
			}
			
			if(!isMessageTypeSupported) {
				System.err.println("The Message Type of the Secure Message Protocol it's not supported!!!");
			
				return false;
			}
			
			return true;
		}
		
		return false;
	}
}