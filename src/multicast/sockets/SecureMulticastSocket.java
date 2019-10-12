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
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.Map;
import multicast.sockets.messages.FinalSecureMessage;
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
	 * The boolean value to keep the information about if
	 * it's the first Message sent/received
	 */
	private boolean firstMessage;
	
	
	
	// Constructors:
	/**
	 * Constructor #1:
	 * - 
	 * 
	 * @throws IOException an Input/Output Exception occurred
	 */
	public SecureMulticastSocket() throws IOException {
		super();
		
		SecureRandom secureRandom = new SecureRandom();
		
		this.randomNonce = secureRandom.nextInt();
		
		this.firstMessage = true;
	}
	
	/**
	 * Constructor #2:
	 * - 
	 * 
	 * @param port the port of the Multicast Group's Address
	 * 
	 * @throws IOException an Input/Output Exception occurred
	 */
	public SecureMulticastSocket(int port) throws IOException {
		super(port);
		
		this.randomNoncesMap = new LinkedHashMap<>();
		
		this.secureMulticastSocketCleaningRandomNoncesService = 
						new SecureMulticastSocketCleaningRandomNoncesService(randomNoncesMap);
		this.secureMulticastSocketCleaningRandomNoncesService.run();
		
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
	 * 
	 * @param
	 */
	@Override
	public void send(DatagramPacket secureMessageDatagramPacketToSend) {
		
		FinalSecureMessage finalSecureMessageToSend = null;
		
		if(this.firstMessage) {
			
			finalSecureMessageToSend = new FinalSecureMessage(secureMessageDatagramPacketToSend, false /* firstMessage */);
			
			this.firstMessage = false;
		}
		else {
			// TODO
		}
		
		try {
			
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
		
		try {
			if(this.firstMessage) {
				this.firstMessage = false;
			}
			else {
				
			}
			
			super.receive(secureMessageDatagramPacketReceived);
		
			FinalSecureMessage finalSecureMessage;
			
			this.randomNoncesMap.put(0, System.currentTimeMillis());
		}
		catch (IOException inputOutputException) {
			System.err.println("Error occurred during the receiving process of the Final Secure Message:");
			System.err.println("- Input/Output error occurred!!!");
			inputOutputException.printStackTrace();
		}
	}
}