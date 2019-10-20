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

		this.secureMessage = new SecureMessage(datagramPacketToBeSent,
				                               fromPeerID, secureMulticastChatSessionParameters,
				                               sequenceNumber, randomNonce, messageType);
		
		this.secureMessage.buildSecureMessageSerialized();
		
		System.out.println("OLE");
		
		this.fastSecureMessageCheck = new FastSecureMessageCheck(this.secureMessage.getSecureMessageSerialized());
		this.fastSecureMessageCheck.buildSecureMessageSerializedHashed();
		
		System.out.println("OLEEEEE");
		
		System.out.println(this.secureMessage.getSecureMessageHeader() != null ? "PASSOU" : "FALHOU");
		
		System.out.println(this.secureMessage.getSecureMessageAttributes() != null ? "PASSOU" : "FALHOU");
		
		System.out.println(this.secureMessage.getSecureMessagePayload() != null ? "PASSOU" : "FALHOU");

		System.out.println(this.fastSecureMessageCheck.getSecureMessageSerializedHashed() != null ? "PASSOU" : "FALHOU");

		
		System.out.println("2º TESTEEEEEEEEEEE");
		
		System.out.println(this.secureMessage.getSecureMessageHeader().getSecureMessageHeaderSerialized() != null ? "PASSOU" : "FALHOU");
		
		System.out.println(this.secureMessage.getSecureMessageAttributes().getSecureMessageAttributesSerialized() != null ? "PASSOU" : "FALHOU");
		
		System.out.println(this.secureMessage.getSecureMessagePayload().getSecureMessagePayloadSerialized() != null ? "PASSOU" : "FALHOU");

		System.out.println(this.fastSecureMessageCheck.getSecureMessageSerializedHashed() != null ? "PASSOU" : "FALHOU");
		
		this.secureMessageMetaHeader = new SecureMessageMetaHeader(this.secureMessage.getSecureMessageHeader().getSecureMessageHeaderSerialized().length,
																   this.secureMessage.getSecureMessageAttributes().getSecureMessageAttributesSerializedHashed().length, 
																   this.secureMessage.getSecureMessagePayload().getSecureMessagePayloadSerialized().length, 
																   this.fastSecureMessageCheck.getSecureMessageSerializedHashed().length);
		
		this.isFinalSecureMessageSerialized = false;
		
		System.out.println("OLEEEEEEEEEE");
	}
	
	/**
	 * 
	 * 
	 * @param datagramPacketToBeSent
	 */
	public FinalSecureMessage(DatagramPacket datagramPacketReceived) {
		this.finalSecureMessageSerialized = datagramPacketReceived.getData();
		System.out.println("RECEBI FINALLLLLLLLLLLLLLLLLLLLL");
		this.isFinalSecureMessageSerialized = true;
	}
	
	/**
	 * Builds the several components of the Final Secure Message serialized.
	 */
	public void buildFinalSecureMessageSerialized() {
		
		if(!this.isFinalSecureMessageSerialized) {
			
			System.out.println("ENTREI NO FINAL");
			
			// META-HEADER
			
			this.secureMessageMetaHeader.buildMessageMetaHeaderSerialized();
			byte[] secureMessageMetaHeaderSerialized = 
					this.secureMessageMetaHeader.getSecureMessageMetaHeaderSerialized();
			
			System.out.println(secureMessageMetaHeader.getSecureMessageMetaHeaderSerialized() != null ? "metaheader serial nao null" : "metaheader serial null");
			
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
			
			System.out.println(secureMessageMetaHeaderSerialized != null ? "PASSOU METAHEADER" : "NAO PASSOU METAHEADER");
			System.out.println(secureMessageSerialized != null ? "PASSOU MESSAGE" : "NAO PASSOU MESSAGE");
			System.out.println(fastSecureMessageCheckSerializedHashed != null ? "PASSOU FAST" : "NAO PASSOU FAST");
			System.out.println(finalSecureMessageSerialized != null ? "PASSOU FINAL" : "NAO PASSOU FINAL");
			
			
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
			
			System.out.println("SIZES:");
			System.out.println("- HEADER: " + this.secureMessageMetaHeader.getSizeOfSecureMessageHeader());
			System.out.println("- ATRIBUTES: " + this.secureMessageMetaHeader.getSizeOfSecureMessageAttributes());
			//System.out.println("- HEADER: " + this.secureMessageMetaHeader.getSizeOfSecureMessageHeader());
			System.out.println("- PAYLOAD: " + this.secureMessageMetaHeader.getSizeOfSecureMessagePayload());
			
			int sizeOfFastSecureMessageCheck = this.secureMessageMetaHeader.getSizeOfFastSecureMessageCheck();
			
			byte[] secureMessage = new byte[sizeOfSecureMessage];
			byte[] fastSecureMessageCheck = new byte[sizeOfFastSecureMessageCheck];
			
			System.out.println("O MESSAGE TEM TAMANHO:");
			System.out.println(sizeOfSecureMessage);
			
			System.out.println("O FAST TEM TAMANHO:");
			System.out.println(sizeOfFastSecureMessageCheck);
			
			
			// Fills the byte array of the Final Secure Message with the Secure Message's Meta-Header,
			// From the initial position to the corresponding to the length of Secure Message's Meta-Header
			System.arraycopy(this.finalSecureMessageSerialized, serializationOffset,
							 secureMessage, 0, secureMessage.length);
			serializationOffset += secureMessage.length;
			
			// Fills the byte array of the Final Secure Message with the Secure Message's Meta-Header,
			// From the initial position to the corresponding to the length of Secure Message's Meta-Header
			System.arraycopy(this.finalSecureMessageSerialized, serializationOffset,
							 fastSecureMessageCheck, 0, fastSecureMessageCheck.length);
			serializationOffset += fastSecureMessageCheck.length;
			
			this.fastSecureMessageCheck = new FastSecureMessageCheck(secureMessage, fastSecureMessageCheck);
			System.out.println(this.fastSecureMessageCheck.checkIfIsSecureMessageSerializedHashedValid() ? "VALIDO" : "INVALIDO");
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
}