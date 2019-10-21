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
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

import multicast.common.MessageType;
import multicast.sockets.messages.FinalSecureMessage;
import multicast.sockets.messages.utils.SecureMulticastChatSessionParameters;
import multicast.sockets.services.SecureMulticastSocketCleaningRandomNoncesService;

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
	 * The Sequence Number, which will be sent or receive
	 */
	private int sequenceNumber;
	
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
	private Map<Integer, Long> randomNoncesMap;
	
	/**
	 * The Secure Multicast Socket Cleaning Random Nonces Service
	 */
	private SecureMulticastSocketCleaningRandomNoncesService secureMulticastSocketCleaningRandomNoncesService;
	
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
	 * - TODO Socket to send
	 * @param secureMulticastChatSessionParameters 
	 * 
	 * @throws IOException an Input/Output Exception occurred
	 */
	public SecureMulticastSocket(String fromPeerID, int port,
								 SecureMulticastChatSessionParameters secureMulticastChatSessionParameters) throws IOException {
		
		super(port);
		
		this.fromPeerID = fromPeerID;
		
		this.secureRandom = new SecureRandom();
		
		this.randomNoncesMap = new LinkedHashMap<>();
		
		this.secureMulticastSocketCleaningRandomNoncesService = 
						new SecureMulticastSocketCleaningRandomNoncesService(randomNoncesMap);
		
		new Thread(this.secureMulticastSocketCleaningRandomNoncesService).start();
		
		this.secureMulticastChatSessionParameters = secureMulticastChatSessionParameters;
		System.out.println(this.secureMulticastChatSessionParameters != null ? "SIIIIIIIIIM2X" : "NAAAAAAAAAAAAO2X");
		this.firstMessage = true;
	}
	
	/**
	 * Constructor #2:
	 * - TODO Socket to receive
	 * 
	 * @param port the port of the Multicast Group's Address
	 * 
	 * @throws IOException an Input/Output Exception occurred
	 */
	public SecureMulticastSocket(Properties properties) throws IOException {
		super();
		
		System.out.println("ESTOU PRONTO PARA RECEBER");
		
		this.randomNoncesMap = new LinkedHashMap<>();
		
		this.secureMulticastSocketCleaningRandomNoncesService = 
						new SecureMulticastSocketCleaningRandomNoncesService(randomNoncesMap);
		
		new Thread(this.secureMulticastSocketCleaningRandomNoncesService).start();
		
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
	 * TODO
	 * @param secureMulticastChatSessionParameters 
	 * 
	 * @param
	 */
	@Override
	public void send(DatagramPacket secureMessageDatagramPacketToSend) {
				
		this.randomNonce = secureRandom.nextInt();
		
		if(this.firstMessage) {
			this.sequenceNumber = 1;
			
			this.firstMessage = false;
		}
		else {
			this.sequenceNumber++;
		}
		
		System.out.println("VOU CONSTRUIR A MENSAGEEEEEEEEEEEEEEEEEM");
		
		System.out.println(this.secureMulticastChatSessionParameters != null ? "SIIIIIIIIIM3X" : "NAAAAAAAAAAAAO3X");
		
		FinalSecureMessage finalSecureMessageToSend = new FinalSecureMessage(secureMessageDatagramPacketToSend,
				                                                             this.fromPeerID, this.secureMulticastChatSessionParameters,
				                                                             this.sequenceNumber, this.randomNonce,
				                                                             MessageType.MESSAGE_TYPE_1.getMessageType());
		System.out.println("AQUIIIIIIIIIIIII VAIIIIIIIIIIIIIIII");
		
		try {
			System.out.println("AAAAAAAABBBBBBBCCCCCCCCCC");
			finalSecureMessageToSend.buildFinalSecureMessageSerialized();
			System.out.println(finalSecureMessageToSend.getFinalSecureMessageSerialized() != null ? "Objecto final serial nao null" : "objeto final serial null");
			
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
	 * TODO
	 * 
	 * @param
	 */
	@Override
	public void receive(DatagramPacket secureMessageDatagramPacketReceived) {
		
		System.out.println("RECEBI QQ COISA");
		try {
			super.receive(secureMessageDatagramPacketReceived);
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
		
		System.out.println(this.sequenceNumber);
		FinalSecureMessage finalSecureMessage = new FinalSecureMessage(secureMessageDatagramPacketReceived);
		finalSecureMessage.buildFinalSecureMessageComponents();
		
		if(this.firstMessage) {	
			// This must be always true in the reception of the First Message
			if(this.randomNoncesMap.isEmpty()) {
				System.out.println(this.sequenceNumber);
			}
			
			this.firstMessage = false;
		}
		else {
			
		}
			
			
			
			this.randomNoncesMap.put(0, System.currentTimeMillis());
	}
}