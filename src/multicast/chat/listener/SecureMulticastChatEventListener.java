package multicast.chat.listener;

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

import java.net.InetAddress;
import java.util.EventListener;

/**
 * 
 * Interface for the Secure Multicast Chat Event Listener, extending the Event Listener.
 * 
 * @supervisor Prof. Henrique Joao Domingos - hj@fct.unl.pt
 * 
 * @author Eduardo Bras Silva (no. 41798) - emf.silva@campus.fct.unl.pt
 * @author Ruben Andre Barreiro (no. 42648) - r.barreiro@campus.fct.unl.pt
 *
 */
public interface SecureMulticastChatEventListener extends EventListener {
	
	// Methods/Functions:
	/**
	 * Method invoked when a User (Client) participant has joined (i.e., sent a JOIN Operation Message).
	 * 
	 * @param username the Username of the User (Client) participant,
	 * 		  who wants to JOIN to the (Secure) Multicast Chat Socket
	 * 
	 * @param hostInetAddress the Host's Inet Address of the User (Client) participant,
	 * 		  who wants to JOIN to the (Secure) Multicast Chat Socket
	 * 
	 * @param port the Port used by the User (Client) participant,
	 * 		  who wants to JOIN to the (Secure) Multicast Chat Socket
	 */
	void secureMulticastChatParticipantJoined(String username, InetAddress hostInetAddress, int port);

	/**
	 * Method invoked when a User (Client) participant has left (i.e., sent a LEAVE Operation Message).
	 * 
	 * @param username the Username of the User (Client) participant,
	 * 		  who wants to LEAVE the (Secure) Multicast Chat Socket
	 * 
	 * @param hostInetAddress the Host's Inet Address of the User (Client) participant,
	 * 		  who wants to LEAVE the (Secure) Multicast Chat Socket
	 * 
	 * @param port the Port used by the User (Client) participant,
	 * 		  who wants to LEAVE the (Secure) Multicast Chat Socket
	 */
	 void secureMulticastChatParticipantLeft(String username, InetAddress hostInetAddress, int port);
	  
	/**
	 * Method invoked when a User (Client) participant has sent a normal message (i.e., sent a TEXT Operation Message).
	 * 
	 * @param username the Username of the User (Client) participant,
	 * 		  who sent a TEXT message to the (Secure) Multicast Chat Socket
	 * 
	 * @param hostInetAddress the Host's Inet Address of the User (Client) participant,
	 * 		  who sent a TEXT message to the (Secure) Multicast Chat Socket
	 * 
	 * @param port the Port used by the User (Client) participant,
	 * 		  who sent a TEXT message to the (Secure) Multicast Chat Socket
	 * 
	 * @param textMessage the TEXT message sent by the User (Client) participant in the (Secure) Multicast Chat Socket
	 */
	 void secureMulticastChatParticipantTextMessageReceived(String username, InetAddress hostInetAddress, int port, 
                             							    String textMessage);
	 
}