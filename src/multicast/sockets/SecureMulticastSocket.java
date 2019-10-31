package multicast.sockets;

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
import java.io.IOException;
import java.net.MulticastSocket;
import java.net.SocketTimeoutException;
import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import multicast.common.MessageType;
import multicast.sockets.messages.FinalSecureMessage;
import multicast.sockets.messages.components.FastSecureMessageCheck;
import multicast.sockets.messages.components.SecureMessage;
import multicast.sockets.messages.components.SecureMessageAttributes;
import multicast.sockets.messages.components.SecureMessageHeader;
import multicast.sockets.messages.components.SecureMessagePayload;
import multicast.sockets.messages.utils.SecureMulticastChatSessionParameters;
import multicast.sockets.messages.utils.SequenceNumberData;
import multicast.sockets.services.SecureMulticastSocketCleaningRandomNoncesService;
import multicast.sockets.services.SecureMulticastSocketCleaningSequenceNumbersService;

/**
 * 
 * Class for the Secure Multicast Socket, extending the Multicast Socket.
 * 
 * @supervisor Prof. Henrique Joao Domingos - hj@fct.unl.pt
 * 
 * @author Eduardo Bras Silva (no. 41798) - emf.silva@campus.fct.unl.pt
 * @author Ruben Andre Barreiro (no. 42648) - r.barreiro@campus.fct.unl.pt
 *
 */
public class SecureMulticastSocket extends MulticastSocket {

	// Global Instance Variables:
	/**
	 * The Username of the User (Client) using this (Secure) Multicast Socket
	 */
	private String fromPeerID;

	/**
	 * The Sequence Number of this object
	 */
	private int sequenceNumber;

	/**
	 * The Map of Sequence Numbers from the other clients
	 */
	private ConcurrentMap<String, SequenceNumberData> sequenceNumberMap;
	
	/**
	 * The Secure Multicast Socket Cleaning Sequence Numbers Service
	 */
	private SecureMulticastSocketCleaningSequenceNumbersService secureMulticastSocketCleaningSequenceNumbersService;
	
	/**
	 * Variable for accessing the Cleaning Sequence Numbers Service
	 */
	private Thread sequenceNumberCleaningThread;
	
	/**
	 * The Secure Random seed, to generate Random Nonces
	 */
	private SecureRandom secureRandom;

	/**
	 * The current Random Nonce, which will be sent or received
	 */
	private int randomNonce;

	/**
	 * The Map of Random Nonces
	 */
	private ConcurrentMap<Integer, Long> randomNoncesMap;

	/**
	 * The Secure Multicast Socket Cleaning Random Nonces Service
	 */
	private SecureMulticastSocketCleaningRandomNoncesService secureMulticastSocketCleaningRandomNoncesService;

	/**
	 * Variable for accessing the Cleaning Random Nonces Service
	 */
	private Thread randomNonceCleaningThread;
	
	/**
	 * The (Secure) Multicast Chat Session's Parameters,
	 * loaded from the User (Client) using this (Secure) Multicast Socket
	 */
	private SecureMulticastChatSessionParameters secureMulticastChatSessionParameters;

	/**
	 * The boolean value to keep the information about if
	 * it's the first Message sent/received
	 */
	private boolean firstMessage;



	// Constructors:
	/**
	 * Constructor #1:
	 * The constructor for the Secure Multicast Socket.
	 * @param secureMulticastChatSessionParameters 
	 * 
	 * @throws IOException an Input/Output Exception occurred
	 */
	public SecureMulticastSocket(String fromPeerID, int port,
			SecureMulticastChatSessionParameters secureMulticastChatSessionParameters) throws IOException {

		super(port);

		this.fromPeerID = fromPeerID;

		this.secureRandom = new SecureRandom();
		
		this.sequenceNumberMap = new ConcurrentHashMap<>();

		this.randomNoncesMap = new ConcurrentHashMap<>();

		this.secureMulticastSocketCleaningSequenceNumbersService =
				new SecureMulticastSocketCleaningSequenceNumbersService(sequenceNumberMap);
		
		sequenceNumberCleaningThread = new Thread(this.secureMulticastSocketCleaningSequenceNumbersService);
		sequenceNumberCleaningThread.start();
		
		this.secureMulticastSocketCleaningRandomNoncesService = 
				new SecureMulticastSocketCleaningRandomNoncesService(randomNoncesMap);

		randomNonceCleaningThread = new Thread(this.secureMulticastSocketCleaningRandomNoncesService);
		randomNonceCleaningThread.start();
		
		new Thread(this.secureMulticastSocketCleaningRandomNoncesService).start();

		this.secureMulticastChatSessionParameters = secureMulticastChatSessionParameters;
		this.firstMessage = true;
	}

	// Methods:
	/**
	 * Returns the current Random Nonce, which will be sent or received.
	 * 
	 * @return the current Random Nonce, which will be sent or received
	 */
	public int getRandomNonce() {
		return this.randomNonce;
	}

	/**
	 * Returns the Map of Random Nonces.
	 * 
	 * @return the Map of Random Nonces
	 */
	public Map<Integer, Long> getRandomNoncesMap() {
		return this.randomNoncesMap;
	}

	/**
	 * Returns the Secure Multicast Socket Cleaning Random Nonces Service.
	 * 
	 * @return the Secure Multicast Socket Cleaning Random Nonces Service
	 */
	public SecureMulticastSocketCleaningRandomNoncesService 
	getSecureMulticastSocketCleaningRandomNoncesService() {

		return this.secureMulticastSocketCleaningRandomNoncesService;
	}

	/**
	 * The boolean value to keep the information about if
	 * it's the first Message sent/received
	 */
	public boolean isFirstMessage() {
		return this.firstMessage;
	}	

	/**
	 * Sends a datagram packet after making the packet secure.
	 * @param secureMessageDatagramPacketToSend the packet to secure and then send
	 */
	@Override
	public void send(DatagramPacket secureMessageDatagramPacketToSend) {

		this.randomNonce = secureRandom.nextInt();

		sequenceNumber++;

		FinalSecureMessage finalSecureMessageToSend = new FinalSecureMessage(secureMessageDatagramPacketToSend,
				this.fromPeerID, this.secureMulticastChatSessionParameters,
				this.sequenceNumber, this.randomNonce,
				MessageType.MESSAGE_TYPE_1.getMessageType());		
		try {
			finalSecureMessageToSend.buildFinalSecureMessageSerialized();

			byte[] finalSecureMessageToSendSerialized = finalSecureMessageToSend.getFinalSecureMessageSerialized();
			secureMessageDatagramPacketToSend.setData(finalSecureMessageToSendSerialized);

			super.send(secureMessageDatagramPacketToSend);
		}
		catch (IOException inputOutputException) {
			System.err.println("Error occurred during the sending process of the Final Secure Message:");
			System.err.println("- Input/Output error occurred!!!");
			inputOutputException.printStackTrace();
		}
	}

	/**
	 * Receives a secured datagram packet and tries to restore it to its original status
	 * should no attempts at tampering hava ocurred.
	 * @param secureMessageDatagramPacketReceived packet received to try to restore
	 */
	@Override
	public void receive(DatagramPacket secureMessageDatagramPacketReceived) {

		long receiveTimestamp = 0;
		try {
			super.receive(secureMessageDatagramPacketReceived);
			receiveTimestamp = System.currentTimeMillis();
		}
		catch(SocketTimeoutException socketTimeoutException) {
			//We don't need to do anything, it is expected behaviour
			//so a loopback may be done.
		}
		catch (IOException inputOutputException) {
			System.err.println("Error occurred during the receiving process of the Final Secure Message:");
			System.err.println("- Input/Output error occurred!!!");
			inputOutputException.printStackTrace();
		}

		FinalSecureMessage finalSecureMessage = new FinalSecureMessage(secureMessageDatagramPacketReceived, secureMulticastChatSessionParameters);
		finalSecureMessage.buildFinalSecureMessageComponents();
		
		FastSecureMessageCheck fastSecureMessageCheck = finalSecureMessage.getFastSecureMessageCheck();
		
		if(fastSecureMessageCheck.isFastSecureMessageCheckValid()) {
			SecureMessage secureMessage = finalSecureMessage.getSecureMessage();
			secureMessage.buildSecureMessageComponents();
			
			SecureMessageHeader secureMessageHeader = secureMessage.getSecureMessageHeader();
			secureMessageHeader.buildSecureMessageHeaderComponents();
			
			if(secureMessageHeader.isVersionNumberAndMessageTypeSupported()) {
				SecureMessageAttributes secureMessageAttributes = secureMessage.getSecureMessageAttributes();
				
				if(secureMessageAttributes.checkIfIsSecureMessageAttributesSerializedHashedValid()) {
					SecureMessagePayload secureMessagePayload = secureMessage.getSecureMessagePayload();
					secureMessagePayload.buildSecureMessagePayloadSerializationSymmetricEncryptionDeciphered();
					
					if(secureMessagePayload.checkIfIsSecureMessagePayloadSerializedSizeValid()) {
						secureMessagePayload.buildSecureMessagePayloadComponents();
						
						if(secureMessagePayload.checkIfIsIntegrityControlHashedSerializedValid()) {
							
							SequenceNumberData data = sequenceNumberMap.get(secureMessageDatagramPacketReceived.getAddress().getHostAddress());
							if(data == null) {
								data = new SequenceNumberData(secureMessagePayload.getSequenceNumber(), receiveTimestamp);
								sequenceNumberMap.put(secureMessageDatagramPacketReceived.getAddress().getHostAddress(), data);
							}

							if(secureMessagePayload.getSequenceNumber() != data.getSequenceNumber()) {
								System.err.println("Not received a Secure Message with the expected Sequence Number:");
								System.err.println("- The Secure Message will be ignored!!!");
							}
							else {
								data.updateSequenceNumber(data.getSequenceNumber() + 1, receiveTimestamp);
								int receivedRandomNonce = secureMessagePayload.getRandomNonce();

								if(secureMessagePayload.getSequenceNumber() != 1 && this.randomNoncesMap.containsKey(receivedRandomNonce)) {
									System.err.println("Received a Secure Message with a duplicate Random Nonce, in a short period time:");
									System.err.println("- The Secure Message will be ignored!!!");
								}
								else {
									this.randomNoncesMap.put(receivedRandomNonce, System.currentTimeMillis());
									secureMessageDatagramPacketReceived.setData(secureMessagePayload.getMessageSerialized());
								}
							}
						}
					}
				}
			}
		}
	}
}