package multicast.chat;

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

import java.io.*;
import java.net.*;

import multicast.chat.listener.SecureMulticastChatEventListener;
import multicast.common.CommonUtils;
import multicast.sockets.SecureMulticastSocket;
import multicast.sockets.messages.utils.SecureMulticastChatSessionParameters;

/**
 * 
 * Class for the Multicast Chat, extending the Thread class.
 * 
 * @supervisor Prof. Henrique Joao Domingos - hj@fct.unl.pt
 * 
 * @author Eduardo Bras Silva (no. 41798) - emf.silva@campus.fct.unl.pt
 * @author Ruben Andre Barreiro (no. 42648) - r.barreiro@campus.fct.unl.pt
 *
 */
public class MulticastChat extends Thread {
	
	// Invariants/Constants:
	/**
	 * The Filename of Properties' File all the information of
	 * the (Secure) Multicast Chat's Session
	 */
	private static final String propertiesFilename = "./res/SMCP.conf";
	
	
	// Global Instance Variables:
	/**
	 * The Multicast Chat Socket,
	 * used to send and receive Protocol Data Units in the Multicast Protocol;
	 * This Multicast Chat Socket it's used to send and receive messages
	 * in the scope of the operation which have place in the Multicast Chat
	 */
	//protected MulticastSocket multicastChatSocket;
		
	/**
	 * The Secure Multicast Chat Socket,
	 * used to send and receive Secure Protocol Data Units in the Secure Multicast Protocol;
	 * This Secure Multicast Chat Socket it's used to send and receive messages
	 * in the scope of the operation which have place in the Secure Multicast Chat
	 */
	protected SecureMulticastSocket secureMulticastChatSocket;

	/**
	 * The Properties' Reader, to retrieve all the information of
	 * the (Secure) Multicast Chat's Session from some Properties' File
	 */
	protected SecureMulticastChatSessionParameters secureMulticastChatSessionParameters;
	
	/**
	 * The Username or NickName of the User (Client) of the (Secure) Multicast Chat
	 */
	protected String userUsername;

	/**
	 * The IP (Secure) Multicast Group in use
	 */
	protected InetAddress ipMulticastGroup;

	/**
	 * The Event Listener of the Events sent by the (Secure) Multicast communication
	 */
	protected SecureMulticastChatEventListener secureMulticastChatEventListener;

	/**
	 * The boolean value of control to keep information about if
	 * the Execution Thread of the (Secure) Multicast Chat it's still active or not
	 */
	protected boolean isSecureMulticastChatActive;
	
	
	// Constructors:
	/**
	 * Constructor #1:
	 * - Constructor of the (Secure) Multicast Chat for an User (Client), who pretends to use it.
	 * 
	 * @param userUsername the Username or Nickname of the User (Client) of
	 *        the (Secure) Multicast Chat
	 * 
	 * @param ipMulticastGroup the IP (Secure) Multicast Group in use
	 * 
	 * @param port the port of the (Secure) Multicast Chat Socket in use
	 * 
	 * @param timeToLive the Time To Live (T.T.L.) used in the communications
	 * 		  over the (Secure) Multicast Chat
	 * 
	 * @param multicastChatEventListener the Event Listener of Events
	 *        sent by (Secure) Multicast communication
	 * 
	 * @throws IOException an Input/Output Exception to be thrown,
	 *         in the case of an Input/Output error occurred 
	 */
	public MulticastChat(String userUsername, InetAddress ipMulticastGroup, int port, 
                         int timeToLive, SecureMulticastChatEventListener secureMulticastChatEventListener) throws IOException {

	    this.userUsername = userUsername;
	    this.ipMulticastGroup = ipMulticastGroup;
	    
	    this.secureMulticastChatSessionParameters = new SecureMulticastChatSessionParameters(propertiesFilename);
	    
	    this.secureMulticastChatEventListener = secureMulticastChatEventListener;
	    
	    this.isSecureMulticastChatActive = true;
	    
	    System.out.println("HHHHHHHHHHHHHH");
	    
	    // Create and Configure the Multicast Chat Socket
	    //this.multicastChatSocket = new MulticastSocket(port);
	    //this.multicastChatSocket.setSoTimeout(CommonUtils.DEFAULT_MULTICAST_SOCKET_TIMEOUT_MILLIS);
	    //this.multicastChatSocket.setTimeToLive(timeToLive);
	    //this.multicastChatSocket.joinGroup(ipMulticastGroup);
	    
	    // Create and Configure the Secure Multicast Chat Socket
	    this.secureMulticastChatSocket = new SecureMulticastSocket(this.userUsername, port, this.secureMulticastChatSessionParameters);
	    
	    System.out.println("JJJJJJJJJJJJKNK");
	    
	    this.secureMulticastChatSocket.setSoTimeout(CommonUtils.DEFAULT_SECURE_MULTICAST_SOCKET_TIMEOUT_MILLIS);
	    this.secureMulticastChatSocket.setTimeToLive(timeToLive);
	    this.secureMulticastChatSocket.joinGroup(ipMulticastGroup);
	
	    // Start the Receiving Operation Messages' Thread
	    this.start();
	    
	    System.out.println("AAAAAAAAAAAAAAAAAAAAADKNFJBNAJFBAJ");
	    
	    // Sends the JOIN Operation Message by the (Secure) Multicast communication
	    this.sendJoinOperationMessage();
	    
	    System.out.println("sdlgjfdobjofdgjmod");
	}
	
	/**
	 * Requests an asynchronous termination of the Execution Thread,
	 * changing the boolean value of control to keep information about if
	 * the same Execution Thread of the (Secure) Multicast Chat it's still active or not
	 * to false and send the LEAVE Operation Message to the (Secure) Multicast Chat
	 * 
	 * @throws IOExceptionan an Input/Output Exception to be thrown,
	 *         in the case of an Input/Output error occurred
	 */
	public void terminate() throws IOException {
		
		// Stops the Receiving Thread and
		this.isSecureMulticastChatActive = false;
		
		// Sends the LEAVE Operation Message by Multicast communication
		sendLeaveOperationMessage();
	} 
	
	/**
	 * Issues an Error Message related to the (Secure) Multicast Socket.
	 * 
	 * @param errorMessage the Error Message related to the (Secure) Multicast Socket
	 *        to be printed/shown
	 */
	protected void printError(String errorMessage) {
		System.err.println(new java.util.Date() + ": SecureMulticastChat: " + errorMessage);
	} 

	/**
	 * Sends a JOIN Operation Message to the (Secure) Multicast Chat.
	 * 
	 * @throws IOExceptionan an Input/Output Exception to be thrown,
	 *         in the case of an Input/Output error occurred
	 */
	protected void sendJoinOperationMessage() throws IOException {
		
		// Creates a Byte Array Output Stream and the Data Output Stream,
		// which this Byte Array Output Stream will be placed
		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		DataOutputStream dataOutputStream = new DataOutputStream(byteArrayOutputStream);
		
		// Writes the information related to the Byte Array Output Stream in
		// the Data Output Stream, which this Byte Array Output Stream will be placed
		dataOutputStream.writeLong(CommonUtils.SECURE_MULTICAST_CHAT_MAGIC_NUMBER);
		dataOutputStream.writeInt(CommonUtils.JOIN_MESSAGE);
		dataOutputStream.writeUTF(this.userUsername);
		
		// Closes the Data Output Stream,
		// which this Byte Array Output Stream was placed
		dataOutputStream.close();
		
		// Creates the Byte Array Data, where the Byte Array Output Stream will be kept
		byte[] byteArrayData = byteArrayOutputStream.toByteArray();
		
		// Creates the final Datagram Packet to be sent,
		// with all the information contained in the Byte Array Data previously created
		DatagramPacket datagramPacketToBeSent = new DatagramPacket(byteArrayData, byteArrayData.length,
																   this.ipMulticastGroup, 
    										   		               this.secureMulticastChatSocket.getLocalPort());
		
		// Sends the final Datagram Packet through the (Secure) Multicast Chat Socket previously created
		this.secureMulticastChatSocket.send(datagramPacketToBeSent);
	} 

	/**
	 * Receives and processes a JOIN Operation Message on the (Secure) Multicast Chat with notification for
	 * the other Participants' Event Listeners.
	 * 
	 * @param dataInputStream the Data Input Stream, containing the information of the User (Client),
	 *        who sent the JOIN Operation Message on the (Secure) Multicast Chat
	 * 
	 * @param inetAddress the Inet Address of the User (Client),
	 *        who sent the JOIN Operation Message on the (Secure) Multicast Chat
	 * 
	 * @param port the Port binded to the (Secure) Multicast Chat Socket, used by the User (Client),
	 *        who sent the JOIN Operation Message on the (Secure) Multicast Chat
	 * 
	 * @throws IOException an Input/Output Exception to be thrown,
	 *         in the case of an Input/Output error occurred
	 */
	protected void receiveAndProcessJoinOperationMessage(DataInputStream dataInputStream,
														 InetAddress inetAddress, 
														 int port) throws IOException {
		
		// The Username or Nickname of the User (Client) who sent the JOIN Operation Message to the (Secure) Multicast Chat 
		String userUsername = dataInputStream.readUTF();

		// Triggers the Event of JOIN of the User (Client) on the (Secure) Multicast Chat,
		// in order to, notify all the other Participants' Event Listeners  
		try {
			this.secureMulticastChatEventListener.secureMulticastChatParticipantJoined(userUsername, inetAddress, port);
    	}
    	catch (Throwable throwableException) {
    		// Empty catch body
    	}
	} 
	
	/**
	 * Sends a LEAVE Operation Message to the (Secure) Multicast Chat.
	 * 
	 * @throws IOExceptionan an Input/Output Exception to be thrown,
	 *         in the case of an Input/Output error occurred
	 */
	protected void sendLeaveOperationMessage() throws IOException {

		// Creates a Byte Array Output Stream and the Data Output Stream,
		// which this Byte Array Output Stream will be placed
		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		DataOutputStream dataOutputStream = new DataOutputStream(byteArrayOutputStream);
		
		// Writes the information related to the Byte Array Output Stream in
		// the Data Output Stream, which this Byte Array Output Stream will be placed
		dataOutputStream.writeLong(CommonUtils.SECURE_MULTICAST_CHAT_MAGIC_NUMBER);
		dataOutputStream.writeInt(CommonUtils.LEAVE_MESSAGE);
		dataOutputStream.writeUTF(this.userUsername);
		
		// Creates the Byte Array Data, where the Byte Array Output Stream will be kept
		byte[] byteArrayData = byteArrayOutputStream.toByteArray();
				
		// Creates the final Datagram Packet to be sent,
		// with all the information contained in the Byte Array Data previously created
		DatagramPacket datagramPacketToBeSent = new DatagramPacket(byteArrayData, byteArrayData.length,
																   this.ipMulticastGroup, 
    										   					   this.secureMulticastChatSocket.getLocalPort());
		
		// Sends the final Datagram Packet through the (Secure) Multicast Chat Socket previously created
		this.secureMulticastChatSocket.send(datagramPacketToBeSent);
	} 
	
	/**
	 * Receives and processes a LEAVE Operation Message on the (Secure) Multicast Chat with notification for
	 * the other Participants' Event Listeners.
	 * 
	 * @param dataInputStream the Data Input Stream, containing the information of the User (Client),
	 *        who sent the LEAVE Operation Message on the (Secure) Multicast Chat
	 * 
	 * @param inetAddress the Inet Address of the User (Client),
	 *        who sent the LEAVE Operation Message on the (Secure) Multicast Chat
	 * 
	 * @param port the Port binded to the (Secure) Multicast Chat Socket, used by the User (Client),
	 *        who sent the LEAVE Operation Message on the (Secure) Multicast Chat
	 * 
	 * @throws IOException an Input/Output Exception to be thrown,
	 *         in the case of an Input/Output error occurred
	 */
	protected void receiveAndProcessLeaveOperationMessage(DataInputStream dataInputStream,
														  InetAddress inetAddress, 
                                						  int port) throws IOException {
		
		// The Username or Nickname of the User (Client) who sent the LEAVE Operation Message to the (Secure) Multicast Chat 
		String userUsername = dataInputStream.readUTF();
		
		// Triggers the Event of LEAVE of the User (Client) on the (Secure) Multicast Chat,
		// in order to, notify all the other Participants' Event Listeners  
		try {
			this.secureMulticastChatEventListener.secureMulticastChatParticipantLeft(userUsername, inetAddress, port);
    	}
    	catch (Throwable throwableException) {
    		// Empty catch body
    	}
	} 
	
	/**
	 * Sends a TEXT Operation Message to the (Secure) Multicast Chat.
	 * 
	 * @param textMessage the real content of the TEXT Operation Message,
	 *        which the User (Client) pretends to send
	 * 
	 * @throws IOExceptionan an Input/Output Exception to be thrown,
	 *         in the case of an Input/Output error occurred
	 */
	public void sendMessage(String textMessage) throws IOException {
		
		// Creates a Byte Array Output Stream and the Data Output Stream,
		// which this Byte Array Output Stream will be placed
		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		DataOutputStream dataOutputStream = new DataOutputStream(byteArrayOutputStream);
		
		// Writes the information related to the Byte Array Output Stream in
		// the Data Output Stream, which this Byte Array Output Stream will be placed
		dataOutputStream.writeLong(CommonUtils.SECURE_MULTICAST_CHAT_MAGIC_NUMBER);
		dataOutputStream.writeInt(CommonUtils.LEAVE_MESSAGE);
		dataOutputStream.writeUTF(this.userUsername);
		dataOutputStream.writeUTF(textMessage);
		
		// Creates the Byte Array Data, where the Byte Array Output Stream will be kept
		byte[] byteArrayData = byteArrayOutputStream.toByteArray();
				
		// Creates the final Datagram Packet to be sent,
		// with all the information contained in the Byte Array Data previously created
		DatagramPacket datagramPacketToBeSent = new DatagramPacket(byteArrayData, byteArrayData.length,
																   this.ipMulticastGroup, 
    										   					   this.secureMulticastChatSocket.getLocalPort());
		
		// Sends the final Datagram Packet through the (Secure) Multicast Chat Socket previously created
		this.secureMulticastChatSocket.send(datagramPacketToBeSent);
	} 
		
	/**
	 * Receives and processes a TEXT Operation Message on the (Secure) Multicast Chat with notification for
	 * the other Participants' Event Listeners.
	 * 
	 * @param dataInputStream the Data Input Stream, containing the information of the User (Client),
	 *        who sent the TEXT Operation Message on the (Secure) Multicast Chat
	 * 
	 * @param inetAddress the Inet Address of the User (Client),
	 *        who sent the TEXT Operation Message on the (Secure) Multicast Chat
	 * 
	 * @param port the Port binded to the (Secure) Multicast Chat Socket, used by the User (Client),
	 *        who sent the TEXT Operation Message on the (Secure) Multicast Chat
	 * 
	 * @throws IOException an Input/Output Exception to be thrown,
	 *         in the case of an Input/Output error occurred
	 */
	protected void receiveAndProcessTextOperationMessage(DataInputStream dataInputStream,
														  InetAddress inetAddress, 
                                						  int port) throws IOException {
		
		// The Username or Nickname of the User (Client) who sent the TEXT Operation Message to the (Secure) Multicast Chat 
		String userUsername = dataInputStream.readUTF();
		
		// The real content of the TEXT Operation Message, which the User (Client) pretends to send
		String textMessage = dataInputStream.readUTF();
		
		// Triggers the Event of TEXT of the User (Client) on the (Secure) Multicast Chat,
		// in order to, notify all the other Participants' Event Listeners  
		try {
			this.secureMulticastChatEventListener.secureMulticastChatParticipantTextMessageReceived(userUsername, inetAddress, port, textMessage);
		}
		catch (Throwable throwableException) {
    		// Empty catch body
		}
	}
	
	/**
	 * Loop to the reception and de-multiplexing of Datagram Packets,
	 * accordingly to the previously defined Operation Messages.
	 */
	public void run() {
		
		// The buffer of default length to keep the data of the Datagram Packet received
		byte[] datagramPacketReceivedBuffer = new byte[CommonUtils.DEFAULT_MESSAGE_DATAGRAM_PACKET_RECEIVED_SIZE];
		
		// The Datagram Packet to keep the information of the Operation Message received
		DatagramPacket datagramPacketReceived = new DatagramPacket(datagramPacketReceivedBuffer, datagramPacketReceivedBuffer.length);

		// The verification of the Datagram Packet related to the Operation Message received,
		// it's only made if the boolean value of control to keep information about if
		// the Execution Thread of the (Secure) Multicast Chat it's still active
		while (this.isSecureMulticastChatActive) {
			
			try {	
				// Sets the length of the Datagram Packet to support the reception of the related data,
				// before the effective reception of the Datagram Packet related to the Operation Message received
				datagramPacketReceived.setLength(datagramPacketReceivedBuffer.length);
				
				// The effective reception of the Datagram Packet related to the Operation Message received
				this.secureMulticastChatSocket.receive(datagramPacketReceived);
				
				// The Data Input Stream to read all the data information contained in the Datagram Packet related to the Operation Message received
				DataInputStream dataInputStream = new DataInputStream(new ByteArrayInputStream(datagramPacketReceived.getData(), 
																							   datagramPacketReceived.getOffset(),
																							   datagramPacketReceived.getLength()));
				
				// The (Secure) Multicast Chat Magic Number of the Operation Message received
				long secureMulticastChatMagicNumber = dataInputStream.readLong();
				
				// The verification of the Datagram Packet related to the Operation Message received
				// only proceeds if the (Secure) Multicast Chat Magic Numbers of respectively both,
				// the Operation Message and (Secure) Multicast Chat itself are different
				if(secureMulticastChatMagicNumber != CommonUtils.SECURE_MULTICAST_CHAT_MAGIC_NUMBER) {
					continue;
				} 
				
				// The code related to the 
				int operationMessageCode = dataInputStream.readInt();
        
				// The effective verification of the Datagram Packet related to the Operation Message received
				switch (operationMessageCode) {
				
					// It's a TEXT Operation Message
					case CommonUtils.JOIN_MESSAGE:
						this.receiveAndProcessJoinOperationMessage(dataInputStream, datagramPacketReceived.getAddress(), datagramPacketReceived.getPort());
						break;
						
					// It's a TEXT Operation Message
					case CommonUtils.LEAVE_MESSAGE:
						this.receiveAndProcessLeaveOperationMessage(dataInputStream, datagramPacketReceived.getAddress(), datagramPacketReceived.getPort());
						break;
					
					// It's a TEXT Operation Message
					case CommonUtils.TEXT_MESSAGE:
						this.receiveAndProcessTextOperationMessage(dataInputStream, datagramPacketReceived.getAddress(), datagramPacketReceived.getPort());
						break;
					
					// The default case (i.e., the Operation Message received it's not recognized by the (Secure) Multicast Chat Protocol)
					default:
						this.printError("Unknown Operation Message's Code " + operationMessageCode + " received from " 
									    + datagramPacketReceived.getAddress() + ":" + datagramPacketReceived.getPort());
				}
			}
			catch (InterruptedIOException interruptedIOException) {
				
				// Empty catch body
				
				// The Timeout it's only used to force a Loopback and
				// test the boolean value of control to keep information about if
				// the Execution Thread of the (Secure) Multicast Chat it's still active or not
				
			}
			catch (Throwable throwableException) {
				
				// Prints/Shows an Error occurred during the Processing of the received Operation Message 
				this.printError("Error occurred during the Processing of the received Operation Message: "
								+ throwableException.getClass().getName() + ": " + throwableException.getMessage());
			}
		} 
		
		try {
			// Tries to close the (Secure) Multicast Chat Socket
			secureMulticastChatSocket.close();
		}
		catch (Throwable throwableException) {
    		// Empty catch body
		}
	} 
}