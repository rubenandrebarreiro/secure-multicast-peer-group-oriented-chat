package multicast.sockets.messages;

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

import java.net.DatagramPacket;

import multicast.common.CommonUtils;
import multicast.sockets.messages.components.FastSecureMessageCheck;
import multicast.sockets.messages.components.SecureMessage;
import multicast.sockets.messages.components.SecureMessageMetaHeader;
import multicast.sockets.messages.components.SecureMessagePayload;
import multicast.sockets.messages.utils.SecureMulticastChatSessionParameters;

/**
 * 
 * Class for the Final Secure Message.
 * 
 * @supervisor Prof. Henrique Joao Domingos - hj@fct.unl.pt
 * 
 * @author Eduardo Bras Silva (no. 41798) - emf.silva@campus.fct.unl.pt
 * @author Ruben Andre Barreiro (no. 42648) - r.barreiro@campus.fct.unl.pt
 *
 */
public class FinalSecureMessage {
	
	// Global Instance Variables:
	/**
	 * The Secure Message's Meta-Header
	 */
	private SecureMessageMetaHeader secureMessageMetaHeader;
	
	
	
	/**
	 * The Secure Message
	 */
	private SecureMessage secureMessage;
	
	/**
	 * The Fast Secure Message's Check
	 */
	private FastSecureMessageCheck fastSecureMessageCheck;
	
	/**
	 * The Final Secure Message serialized
	 */
	private byte[] finalSecureMessageSerialized;
	
	/**
	 * The boolean to keep the value to check if
	 * the Final Secure Message is serialized
	 */
	private boolean isFinalSecureMessageSerialized;
	
	private SecureMulticastChatSessionParameters secureMulticastChatSessionParameters;
	
	
	
	// Constructors:
	/**
	 * TODO
	 * @param secureMulticastChatSessionParameters 
	 * 
	 * @param datagramPacket
	 * 
	 * @param
	 */
	public FinalSecureMessage(DatagramPacket datagramPacketToBeSent,
			                  String fromPeerID, SecureMulticastChatSessionParameters secureMulticastChatSessionParameters,
							  int sequenceNumber, int randomNonce, byte messageType) {
		
		// TODO confirmar

		this.secureMulticastChatSessionParameters = secureMulticastChatSessionParameters;
		
		this.secureMessage = new SecureMessage(datagramPacketToBeSent,
				                               fromPeerID, this.secureMulticastChatSessionParameters,
				                               sequenceNumber, randomNonce, messageType);
		
		this.secureMessage.buildSecureMessageSerialized();
				
		this.fastSecureMessageCheck = new FastSecureMessageCheck(this.secureMessage.getSecureMessageSerialized(), secureMulticastChatSessionParameters);
		this.fastSecureMessageCheck.buildSecureMessageSerializedHashed();
		
		SecureMessagePayload secureMessagePayload = this.secureMessage.getSecureMessagePayload();
		
		this.secureMessageMetaHeader = new SecureMessageMetaHeader(this.secureMessage.getSecureMessageHeader().getSecureMessageHeaderSerialized().length,
																   this.secureMessage.getSecureMessageAttributes().getSecureMessageAttributesSerializedHashed().length, 
																   this.secureMessage.getSecureMessagePayload().getSecureMessagePayloadSerialized().length,
																   CommonUtils.fromStringToByteArray(fromPeerID).length,
																   secureMessagePayload.getMessageSerialized().length,
																   secureMessagePayload.getIntegrityControlSerialiazedHashed().length,
																   this.fastSecureMessageCheck.getSecureMessageSerializedHashed().length);
		
		int a = this.fastSecureMessageCheck.getSecureMessageSerializedHashed().length;
		
		this.isFinalSecureMessageSerialized = false;
		
	}
	
	/**
	 * 
	 * 
	 * @param secureMulticastChatSessionParameters
	 * @param datagramPacketToBeSent
	 */
	public FinalSecureMessage(DatagramPacket datagramPacketReceived, SecureMulticastChatSessionParameters secureMulticastChatSessionParameters) {
		this.finalSecureMessageSerialized = datagramPacketReceived.getData();
		this.secureMulticastChatSessionParameters = secureMulticastChatSessionParameters;
		this.isFinalSecureMessageSerialized = true;
	}
	
	/**
	 * Builds the several components of the Final Secure Message serialized.
	 */
	public void buildFinalSecureMessageSerialized() {
		
		if(!this.isFinalSecureMessageSerialized) {
						
			// META-HEADER
			
			this.secureMessageMetaHeader.buildMessageMetaHeaderSerialized();
			byte[] secureMessageMetaHeaderSerialized = 
					this.secureMessageMetaHeader.getSecureMessageMetaHeaderSerialized();
						
			// SECURE MESSAGE
			this.secureMessage.buildSecureMessageSerialized();
			byte[] secureMessageSerialized = 
					this.secureMessage.getSecureMessageSerialized();
			
			// FAST SECURE MESSAGE CHECK
			this.fastSecureMessageCheck.buildSecureMessageSerializedHashed();
			byte[] fastSecureMessageCheckSerializedHashed =
					this.fastSecureMessageCheck.getSecureMessageSerializedHashed();
			 
			this.finalSecureMessageSerialized = new byte[( secureMessageMetaHeaderSerialized.length 
													     + secureMessageSerialized.length 
					                                     + fastSecureMessageCheckSerializedHashed.length )];			
			
			// Operations to Fill a Byte Array, with the following parameters:
			// 1) src - The source of the array to be copied
			// 2) srcPos - The position from the array to be copied, representing the first element to be copied
			// 3) dest - The destination of the array to be copied
			// 4) destPos - The position of the array where will be placed the new copy,
			//              representing the first element where new data will be placed
			// 5) length - The length of the data to be copied from the source array to the destination array
			
			// The offset related to fulfillment of the serialization process
			int serializationOffset = 0;
			
			// Fills the byte array of the Final Secure Message with the Secure Message's Meta-Header,
			// From the initial position to the corresponding to the length of Secure Message's Meta-Header
			System.arraycopy(secureMessageMetaHeaderSerialized, 0,
							 this.finalSecureMessageSerialized, serializationOffset, secureMessageMetaHeaderSerialized.length);
			serializationOffset += secureMessageMetaHeaderSerialized.length;
				
			// Fills the byte array of the Final Secure Message with the Secure Message's components,
			// From the position corresponding to the length of Secure Message's Meta-Header components to
			// the corresponding to the length of Secure Message's components
			System.arraycopy(secureMessageSerialized, 0,
							 this.finalSecureMessageSerialized, serializationOffset, secureMessageSerialized.length);
			serializationOffset += secureMessageSerialized.length;
			
			// Fills the byte array of the Final Secure Message with the Fast Secure Message's Check,
			// From the position corresponding to the length of Secure Message's components to
			// the corresponding to the length of Fast Secure Message's Check
			System.arraycopy(fastSecureMessageCheckSerializedHashed, 0,
							 this.finalSecureMessageSerialized, serializationOffset, fastSecureMessageCheckSerializedHashed.length);
			serializationOffset += fastSecureMessageCheckSerializedHashed.length;
			
			
			// The Final Secure Message have already its serialization done
			this.isFinalSecureMessageSerialized = true;
		}
	}
	
	/**
	 * Builds the several components of the Final Secure Message. TODO IMPORTANTEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE
	 */
	public void buildFinalSecureMessageComponents() {
		if(this.isFinalSecureMessageSerialized) {
			// The size of the Secure Message's Meta-Header serialized
			int sizeOfSecureMessageMetaHeaderSerialized = ( ( CommonUtils.NUM_COMPONENTS_META_HEADER * CommonUtils.INTEGER_IN_BYTES_LENGTH ) + 
									                        ( CommonUtils.META_HEADER_OUTSIDE_SEPARATORS * CommonUtils.META_HEADER_OUTSIDE_SEPARATORS_LENGTH ) + 
									                        ( CommonUtils.META_HEADER_INSIDE_SEPARATORS * CommonUtils.META_HEADER_INSIDE_SEPARATORS_LENGTH ) );
			
			byte[] secureMessageMetaHeaderSerialized = new byte[sizeOfSecureMessageMetaHeaderSerialized];
			
			// Operations to Fill a Byte Array, with the following parameters:
			// 1) src - The source of the array to be copied
			// 2) srcPos - The position from the array to be copied, representing the first element to be copied
			// 3) dest - The destination of the array to be copied
			// 4) destPos - The position of the array where will be placed the new copy,
			//              representing the first element where new data will be placed
			// 5) length - The length of the data to be copied from the source array to the destination array
			
			// The offset related to fulfillment of the serialization process
			int serializationOffset = 0;
			
			//TODO - mudar comentarios
			// Fills the byte array of the Final Secure Message with the Secure Message's Meta-Header,
			// From the initial position to the corresponding to the length of Secure Message's Meta-Header
			System.arraycopy(this.finalSecureMessageSerialized, serializationOffset,
							 secureMessageMetaHeaderSerialized, 0, secureMessageMetaHeaderSerialized.length);
			serializationOffset += secureMessageMetaHeaderSerialized.length;
			
			
			
			this.secureMessageMetaHeader = new SecureMessageMetaHeader(secureMessageMetaHeaderSerialized);
			this.secureMessageMetaHeader.buildSizesOfSecureMessageComponents();
			
			
			
			int sizeOfSecureMessage = this.secureMessageMetaHeader.getSizeOfSecureMessage();
						
			byte[] secureMessageSerialized = new byte[sizeOfSecureMessage];
			
			// Fills the byte array of the Final Secure Message with the Secure Message,
			// From the initial position to the corresponding to the length of Secure Message
			System.arraycopy(this.finalSecureMessageSerialized, serializationOffset,
							 secureMessageSerialized, 0, secureMessageSerialized.length);
			serializationOffset += secureMessageSerialized.length;
						
			
			
			int sizeOfFastSecureMessageCheck = this.secureMessageMetaHeader.getSizeOfFastSecureMessageCheck();
			
			byte[] fastSecureMessageCheck = new byte[sizeOfFastSecureMessageCheck];			

			// Fills the byte array of the Final Secure Message with the Fast Secure Message Check,
			// From the initial position to the corresponding to the length of Secure Message's Meta-Header
			System.arraycopy(this.finalSecureMessageSerialized, serializationOffset,
							 fastSecureMessageCheck, 0, fastSecureMessageCheck.length);
			serializationOffset += fastSecureMessageCheck.length;
			
			this.fastSecureMessageCheck = new FastSecureMessageCheck(secureMessageSerialized, fastSecureMessageCheck, this.secureMulticastChatSessionParameters);
			
			if(this.fastSecureMessageCheck.isFastSecureMessageCheckValid()) {
				
				int sizeOfSecureMessageHeader = this.secureMessageMetaHeader.getSizeOfSecureMessageHeader();
				int sizeOfSecureMessageAttributes = this.secureMessageMetaHeader.getSizeOfSecureMessageAttributes();
				int sizeOfSecureMessagePayload = this.secureMessageMetaHeader.getSizeOfSecureMessagePayload();
				int sizeOfFromPeerID = this.secureMessageMetaHeader.getSizeOfFromPeerID();
				int sizeOfMessage = this.secureMessageMetaHeader.getSizeOfMessage();
				int sizeOfIntegrityControl = this.secureMessageMetaHeader.getSizeOfIntegrityControl();
				
				this.secureMessage = new SecureMessage(secureMessageSerialized, sizeOfSecureMessageHeader,
						                               sizeOfSecureMessageAttributes, sizeOfSecureMessagePayload,
						                               sizeOfFromPeerID, sizeOfMessage, sizeOfIntegrityControl,
						                               secureMulticastChatSessionParameters);
				
				this.isFinalSecureMessageSerialized = false;
			}
		}
	}
	
	/**
	 * Returns the final Secure Message serialized.
	 * 
	 * @return the final Secure Message serialized
	 */
	public byte[] getFinalSecureMessageSerialized() {
		return this.isFinalSecureMessageSerialized ? this.finalSecureMessageSerialized : null;
	}
	
	/**
	 * TODO
	 * @return
	 */
	public SecureMessageMetaHeader getSecureMessageMetaHeader() {
		return this.isFinalSecureMessageSerialized ? null : this.secureMessageMetaHeader;
	}
	
	/**
	 * TODO
	 * @return
	 */
	public SecureMessage getSecureMessage() {
		return this.isFinalSecureMessageSerialized ? null : this.secureMessage;
	}
	
	/**
	 * TODO
	 * @return
	 */
	public FastSecureMessageCheck getFastSecureMessageCheck() {
		return this.fastSecureMessageCheck;
	}
}