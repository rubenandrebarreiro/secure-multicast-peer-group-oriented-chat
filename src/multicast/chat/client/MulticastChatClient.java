package multicast.chat.client;

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

import java.io.IOException;
import java.net.InetAddress;
import java.text.DateFormatSymbols;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;

import multicast.chat.MulticastChat;
import multicast.chat.listener.SecureMulticastChatEventListener;
import multicast.common.CommonUtils;

import java.util.*;

/**
 * 
 * Class for the Multicast Chat Client,
 * extending the JFrame class and
 * implementing the Interface for the Secure Multicast Chat Event Listener.
 * 
 * NOTES:
 * - This it's the interface for the Swing-Based Chat's Session and
 *   can be improved, in order to, support the several functionalities of
 *   the (Secure) Multicast Chat itself.
 * 
 * @supervisor Prof. Henrique Joao Domingos - hj@fct.unl.pt
 * 
 * @author Eduardo Bras Silva (no. 41798) - emf.silva@campus.fct.unl.pt
 * @author Ruben Andre Barreiro (no. 42648) - r.barreiro@campus.fct.unl.pt
 *
 */
public class MulticastChatClient extends JFrame implements SecureMulticastChatEventListener {
	
	// Invariants/Constants:
	/**
	 * The default serial version ID
	 */
	private static final long serialVersionUID = 1L;

	
	// Global Instance Variables:
	/**
	 * The (Secure) Multicast Chat
	 */
	protected MulticastChat multicastChat;
	
	/**
	 * The JTextArea of the current available Operation Messages,
	 * exchanged between the Users (Clients) participating in the
	 * (Secure) Multicast Chat, including the JOIN and TEXT Operations' Messages
	 */
	protected JTextArea conversationMulticastChatTextArea;

	/**
	 * The JTextField, which can be entered the TEXT Operation Messages
	 */
	protected JTextField messageTextAreaField;
	
	/**
	 * The JTextField for the text field, which can be entered a file to download
	 * through the (Secure) Multicast Chat's Session
	 */
	protected JTextField downloadFileTextField;
	
	/**
	 * The Default List Model containing all the online Users
	 * currently online in the (Secure) Multicast Chat
	 */
	protected DefaultListModel<String> onlineUsersList;
	
	
	// Constructors:
	/**
	 * Constructor #1:
	 * - Constructor for the Multicast Chat Client,
	 *   initializing also its several components of the Graphic User Interface (G.U.I.) and
	 *   the Chat's Session (initialized with the state of Disconnected or Not Connected)
	 */
	public MulticastChatClient() {
		super("(Secure) Multicast Chat (Mode: Disconnected)");

		// Builds and sets the several components of the Graphic User Interface (G.U.I.),
		// related to the (Secure) Multicast Chat for
		// the initializing of the Chat's Session
		
		// Builds and sets the JTextArea of the current available Operation Messages,
		// exchanged between the Users (Clients) participating in the
		// (Secure) Multicast Chat, including the JOIN and TEXT Operations' Messages
		this.conversationMulticastChatTextArea = new JTextArea();
		this.conversationMulticastChatTextArea.setEditable(false);
		this.conversationMulticastChatTextArea.setLineWrap(true);
		this.conversationMulticastChatTextArea.setBorder(BorderFactory.createLoweredBevelBorder());
		
		// Builds, sets and binds a JScrollPane to the JTextArea of the current available Operation Messages,
		// exchanged between the Users (Clients) participating in the
		// (Secure) Multicast Chat, including the JOIN and TEXT Operations' Messages
		JScrollPane textAreaScrollPane = new JScrollPane(this.conversationMulticastChatTextArea, 
														 JScrollPane.VERTICAL_SCROLLBAR_ALWAYS, 
														 JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
		
		// Adds the previously created/built JScrollPane to the main JFrame's Content
		this.getContentPane().add(textAreaScrollPane, BorderLayout.CENTER);
		
		// Builds, sets and binds the JList of currently Online Users in the (Secure) Multicast Chat's Session
		this.onlineUsersList = new DefaultListModel<String>();
		JList<String> onlineUsersJList = new JList<String>(onlineUsersList);
		
		// Builds, sets and binds a JScrollPane to
		// the JList of currently Online Users in the (Secure) Multicast Chat's Session
		JScrollPane onlineUsersListJScrollPane = new JScrollPane(onlineUsersJList, 
														 		 JScrollPane.VERTICAL_SCROLLBAR_ALWAYS, 
														 		 JScrollPane.HORIZONTAL_SCROLLBAR_NEVER) {
			// Invariants/Constants:
			/**
			 * The default serial version ID
			 */
			private static final long serialVersionUID = 1L;
			
			/**
			 * Returns the minimum size of the JScrollPane to
			 * the JList of currently Online Users in the Chat's Session.
			 * 
			 * @return the minimum size of the JScrollPane to
			 *         the JList of currently Online Users in the Chat's Session 
			 */
			public Dimension getMinimumSize() {
				Dimension minimumSizeDimension = super.getMinimumSize();
				minimumSizeDimension.width = 100;
				
				return minimumSizeDimension;
			}
			
			/**
			 * Returns the preferred size of the JScrollPane to
			 * the JList of currently Online Users in the Chat's Session.
			 * 
			 * @return the preferred size of the JScrollPane to
			 *         the JList of currently Online Users in the Chat's Session
			 */
			public Dimension getPreferredSize() {
				Dimension minimumSizeDimension = super.getPreferredSize();
				minimumSizeDimension.width = 100;
			
				return minimumSizeDimension;
			}
		};
		
		// Adds the previously created/built JScrollPane to the main JFrame's Content, in the west (left) side
		this.getContentPane().add(onlineUsersListJScrollPane, BorderLayout.WEST);
		
		// Creates a Box of Components binded to Y axis
		Box box = new Box(BoxLayout.Y_AXIS);
		
		// Adds a first vertical orientation to the Box previously created
		box.add(Box.createVerticalGlue());
		
		// The JPanel related to the field to insert new messages to send to
		// the (Secure) Multicast Chat's Session
		JPanel insertMessagePanel = new JPanel(new BorderLayout());
		
		// Adds the label "Message" to the JPanel previously created, in the left (west) side
		insertMessagePanel.add(new JLabel("Message:"), BorderLayout.WEST);
		
		// Creates the JTextField, which can be entered the TEXT Operation Messages
		this.messageTextAreaField = new JTextField();
		
		// Adds a Action Event Listener to the JTextField, where can be entered the TEXT Operation Messages
		this.messageTextAreaField.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent actionEvent) {
				sendTextMessage();
			}
		});
		
		// Adds the JTextField, which can be entered the TEXT Operation Messages to
		// the JPanel previously created, in the middle (center) side
		insertMessagePanel.add(this.messageTextAreaField, BorderLayout.CENTER);

		// Creates the JButton labeled "SEND"
		JButton sendTextMessageButton = new JButton("  SEND  ");
		
		// Adds a Action Event Listener to the the JButton labeled "SEND",
		// which can be clicked to send the entered the TEXT Operation Messages
		sendTextMessageButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent actionEvent) {
				sendTextMessage();
			}
		});
		
		// Adds the JButton labeled "SEND", which can be clicked to send the entered the TEXT Operation Messages to
		// the JPanel previously created, in the east (right) side
		insertMessagePanel.add(sendTextMessageButton, BorderLayout.EAST);
		
		// Adds the JPanel previously created, in the middle (center) side to
		// the previously created Box
		box.add(insertMessagePanel);

		// Adds a second vertical orientation to the Box previously created
		box.add(Box.createVerticalGlue());
		
		// Creates the JPanel, which allow to download files through the (Secure) Multicast Chat's Session
		JPanel downloadFilePanel = new JPanel(new BorderLayout());

		// Adds the label "Not Used" to the JPanel previously created, in the left (west) side
		downloadFilePanel.add(new JLabel("Not Used" /* TODO - Change it to be able to download files through the (Secure) Multicast Chat's Session */),
					  		  BorderLayout.WEST);
		
		// Creates the JTextField for the text field, where can be entered a file to download through the (Secure) Multicast Chat's Session
		this.downloadFileTextField = new JTextField();
		
		// Adds a Action Event Listener to the JTextField, where can be entered a file to download through the (Secure) Multicast Chat's Session
		this.downloadFileTextField.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent actionEvent) {
				downloadFile();
			}
		});
		
		// Adds the JTextField for the text field, which can be entered a file to download through the (Secure) Multicast Chat's Session to
		// the JPanel previously created, in the middle (center) side
		downloadFilePanel.add(this.downloadFileTextField, BorderLayout.CENTER);
		
		// Creates the JButton labeled "Not Implemented"
		JButton downloadFileButton = new JButton("Not Implemented" /* TODO - Change it to be able to download files through the (Secure) Multicast Chat's Session */);
		
		// Adds a Action Event Listener to the the JButton labeled "Not Implemented",
		// which can be clicked to download files through the (Secure) Multicast Chat's Session
		downloadFileButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent actionEvent) {
				downloadFile();
			}
		});
		
		// Adds the JButton labeled "Not Implemented", which can be clicked to download files through the (Secure) Multicast Chat's Session from
		// the JPanel previously created, in the east (right) side
		downloadFilePanel.add(downloadFileButton, BorderLayout.EAST);
		
		// Adds the JPanel previously created, in the right (east) side to
		// the previously created Box
		box.add(downloadFilePanel);
		
		// Adds a third vertical orientation to the Box previously created
		box.add(Box.createVerticalGlue());
		
		// Adds the previously created/built Box to the main JFrame's Content, in the south (bottom) side
		this.getContentPane().add(box, BorderLayout.SOUTH);
		
		// Adds the Event Listener to the Frame/Window of the (Secure) Multicast Chat's Session
		this.addWindowListener(new WindowAdapter() {
			
			// Invoked in the first time that Frame/Window of
			// the (Secure) Multicast Chat's Session is set as visible
			public void windowOpened(WindowEvent windowEvent) {
				messageTextAreaField.requestFocus();
			} 
			
			// Terminates the which joined to the (Secure) Multicast Chat's Session
			// when the closing of its Frame/Window happened
			public void windowClosing(WindowEvent windowEvent) {
				onQuit();
				dispose();
			} 
			
			// Exits the Application of the (Secure) Multicast Chat's Session
			public void windowClosed(WindowEvent windowEvent) {
				System.exit(0);
			} 
		});
	}
	
	/**
	 * Adds an User (Client) which joined to the (Secure) Multicast Chat's Session to
	 * the List of Online Users in its Graphic User Interface (G.U.I.), given his Username.
	 * 
	 * @param userUsername the Username of the User (Client)
	 *        which joined to the (Secure) Multicast Chat's Session
	 */
	protected void addUserToTheOnlineUsersList(String userUsername) {
		this.onlineUsersList.addElement(userUsername);
	}
	
	/**
	 * Removes an User (Client) who left to the (Secure) Multicast Chat's Session from
	 * the List of Online Users in its Graphic User Interface (G.U.I.), given his Username.
	 * 
	 * @param userUsername the Username of the User (Client)
	 *        which left to the (Secure) Multicast Chat's Session
	 * 
	 * @return the Username of the removed User (Client) who left 
	 * 		   the (Secure) Multicast Chat's Session from
	 *         the List of Online Users in its Graphic User Interface (G.U.I.)
	 */
	protected boolean removeUserFromTheOnlineUsersList(String userUsername) {
		return this.onlineUsersList.removeElement(userUsername);
	}
	
	/**
	 * Initializes and iterates the elements of an Iterator of all the Usernames of the Users (Clients),
	 * currently online/active Users (Clients) the List of Online Users in its Graphic User Interface (G.U.I.).
	 * 
	 * @param onlineUsersListIterator the Iterator of all the Usernames of the Users (Clients),
	 *		  currently online/active Users (Clients) the List of Online Users in its Graphic User Interface (G.U.I.)
	 */
	protected void iteratesAllTheOnlineUsersList(Iterator<String> onlineUsersListIterator) {
		this.onlineUsersList.clear();
		
		if(onlineUsersListIterator != null) {
			while(onlineUsersListIterator.hasNext()) {
				this.onlineUsersList.addElement(onlineUsersListIterator.next());
			}
		}
	}
	
	/**
	 * Returns all the Usernames of the Users (Clients),
	 * currently online/active Users (Clients) the List of Online Users in its Graphic User Interface (G.U.I.). 
	 * 
	 * @return all the Usernames of the Users (Clients),
	 * 		   currently online/active Users (Clients) the List of Online Users in its Graphic User Interface (G.U.I.)
	 */
	protected Enumeration<String> getOnlineUsersList() {
		return this.onlineUsersList.elements();
	}
	
	// Configuracao do grupo multicast da sessao de chat na interface do cliente
	
	/**
	 * 
	 * 
	 * @param userUsername
	 * 
	 * @param ipMulticastGroup
	 * 
	 * @param port
	 * 
	 * @param timeToLive
	 * 
	 * @throws IOException
	 */
	public void joinOperationToTheMulticastChatSession(String userUsername,
					 								   InetAddress ipMulticastGroup, int port, int timeToLive) throws IOException {
		
		// Sets the title of the 
		this.setTitle("(Secure) Multicast Chat IP - " + userUsername + " @ " + ipMulticastGroup.getHostAddress() 
				      + ":" + port + " | [Time To Live (T.T.L.) = " + timeToLive + "]");
		
		// Creates a (Secure) Multicast Chat's Session
		this.multicastChat = new MulticastChat(userUsername, ipMulticastGroup, port, timeToLive, this);
	} 
	
	/**
	 * Logs a TEXT Message, given the content bo be assigned to it.
	 * 
	 * @param textMessageLog the content of the TEXT Message's Log
	 */
	protected void textMessageLog(final String textMessageLog) {
		
		// The Date's Object representation 
		Date date = new Date();
		
		// The Calendar's Object representation
		//Calendar calendar = new GregorianCalendar();

		SwingUtilities.invokeLater(new Runnable() {
			public void run() {
				
				// The Date Format Symbols' Object representation
				DateFormatSymbols dateFormatSymbols = new DateFormatSymbols();
				
				// The conversion of the Month's numerical representation to text representation
				@SuppressWarnings("deprecation")
				String month = dateFormatSymbols.getMonths()[date.getMonth()];
				
				// The formation of the Time's 24-Hours representation
				@SuppressWarnings("deprecation")
				String time24HoursNotation = String.format("%d:%d",
														   date.getHours(), date.getMinutes());
				
				// The conversion of the Time's 24-Hours representation to the Time's 12-Hours [AM|PM] representation
				String time12HoursAMPMNotation = LocalTime.parse(time24HoursNotation).format(DateTimeFormatter.ofPattern("h:mma"));
				
				// The final formation of the Time and Date representation to be appended to the TEXT Message's Log
				@SuppressWarnings("deprecation")
				String timeAndDateLogMessageStringFormat = String.format("%s, %s %d, %d - %s",
																		 date.getDay(), month, date.getDate(), date.getYear(),
																		 time12HoursAMPMNotation);
				
				// Appends the final formation of the Time and Date representation to the TEXT Message's Log
				conversationMulticastChatTextArea.append(timeAndDateLogMessageStringFormat + "\n- " + textMessageLog);
			} 
		});
	} 

	/**
	 * Sends a TEXT Message, through the (Secure) Multicast Chat's Session.
	 *
	 * NOTES:
	 * - It's called when the "SEND" button it's clicked or when the "ENTER" key on the keyboard it's pressed;
	 * - Performs the operations related to the Graphic User Interface (G.U.I.);
	 */
	protected void sendTextMessage() {
		
		// Retrieves the TEXT Message from the JTextField, which can be entered the TEXT Operation Messages
		String textMessage = this.messageTextAreaField.getText();
		
		// Resets the content of the JTextField, which can be entered the TEXT Operation Messages
		this.messageTextAreaField.setText("");
		
		// Performs the effective sending of the TEXT Message
		this.performTheSendTextMessageOperations(textMessage);
		
		this.messageTextAreaField.requestFocus();
	}

	/**
	 * Performs the operations related to the sending of the TEXT Messages.
	 * 
	 * NOTES:
	 * - It's called after the "SEND" button be clicked or after the "ENTER" key on the keyboard be pressed;
	 * 
	 * @param textMessage the TEXT Message to be sent, through the (Secure) Multicast Chat's Session
	 */
	protected void performTheSendTextMessageOperations(String textMessage) {
		
		// Sends the TEXT Message through the (Secure) Multicast Chat's Session
		try {
			this.multicastChat.sendMessage(textMessage);
		}
		catch (Throwable throwableException) {
			JOptionPane.showMessageDialog(this, "Error during the sending of the message: " 
										  + throwableException.getMessage(), "(Secure) Multicast Chat's Session Error", 
								          JOptionPane.ERROR_MESSAGE);
		} 
	}
	
	/**
	 * Requests the Download of a File, through the (Secure) Multicast Chat's Session.
	 *
	 * NOTES:
	 * - It's called when the "SEND" button it's clicked or when the "ENTER" key on the keyboard it's pressed,
	 *   in the Download's Text Field;
	 * - Performs the operations related to the Graphic User Interface (G.U.I.);
	 */
	protected void downloadFile() {
		
		final String file = downloadFileTextField.getText();
		
		this.downloadFileTextField.setText("");
		
		new Thread(new Runnable() {
			public void run() {
				performTheDownloadFileOperation(file);
			}
		}).start();
	
		this.messageTextAreaField.requestFocus();
	}
	
	/**
	 * Performs the operations related to the downloading of files.
	 * 
	 * NOTES:
	 * - It's called when the "SEND" button it's clicked or when the "ENTER" key on the keyboard it's pressed,
	 *   in the Download's Text Field;
	 * - Any information to be displayed to the User (Client) of the (Secure) Multicast Chat's Session,
	 *   using the auxiliary method/function "displayErrorMessage";
	 * 
	 * @param fileName the name of the file to have its download made
	 */
	protected void performTheDownloadFileOperation(String fileName) {
		// TODO - To Complete
		System.err.println("Request of File Download: " + fileName);
	}
	
	/**
	 * Prints/Shows an Error Message, during the communications over the (Secure) Multicast Chat's Session.
	 * 
	 * @param errorMessage the Error Message to be displayed
	 * 
	 * @param isError the boolean value to keep the information about if the Error Message it's really due to
	 *        an Error occurred over the (Secure) Multicast Chat's Session or not
	 */
	protected void displayErrorMessage(final String errorMessage, final boolean isError) {
		final JFrame displayErrorMessageFrame = this;

		SwingUtilities.invokeLater(new Runnable() {
			public void run() {
				
				// The Error Message it's really due to an Error occurred over the (Secure) Multicast Chat's Session
				if(isError) {
					JOptionPane.showMessageDialog(displayErrorMessageFrame, errorMessage,
							                      "Error occurred on (Secure) Multicast Chat's Session", JOptionPane.ERROR_MESSAGE);
				}
				// The Error Message it's not due to an Error occurred over the (Secure) Multicast Chat's Session
				else {
					JOptionPane.showMessageDialog(displayErrorMessageFrame, errorMessage,
							                      "Information related to (Secure) Multicast Chat's Session", JOptionPane.INFORMATION_MESSAGE);
				}
			}
		});
	}
	
	/**
	 * Performs the operations related to the closing of the Frame/Window of the (Secure) Multicast Chat's Session.
	 */
	protected void onQuit() {
		try {
			// If the (Secure) Multicast Chat's Session it's not null
			if(this.multicastChat != null) {
				this.multicastChat.terminate();
			} 
		}
		catch (Throwable throwableException) {
			JOptionPane.showMessageDialog(this, "Error during the termination of the (Secure) Multicast Chat's Session:  "
										  + throwableException.getMessage(), "ERROR on the (Secure) Multicast Chat's Session", 
										  JOptionPane.ERROR_MESSAGE);
		}
	}

	/**
	 * Method/Function invoked when it's received a JOIN Operation Message from an User (Client),
	 * through the (Secure) Multicast Chat's Session.
	 */
	public void secureMulticastChatParticipantJoined(String userUsername, InetAddress userINETAddress, int port) {
		this.textMessageLog("A NEW PARTICIPANT JOINED:\n- " + userUsername
				            + " has joined to the Multicast Chat's Group, from the following IP Address [" 
				            + userINETAddress.getHostName() + ":" + port + "]");
	} 

	/**
	 * Method/Function invoked when it's received a LEAVE Operation Message from an User (Client),
	 * through the (Secure) Multicast Chat's Session.
	 */
	public void secureMulticastChatParticipantLeft(String userUsername, InetAddress userINETAddress, int port) {
		this.textMessageLog("A PARTICIPANT LEFT:\n- " + userUsername
				            + " has left the Multicast Chat's Group, from the following IP Address [" 
				            + userINETAddress.getHostName() + ":" + port);
	} 

	/**
	 * Method/Function invoked when it's received a TEXT Operation Message from an User (Client),
	 * through the (Secure) Multicast Chat's Session.
	 */
	public void secureMulticastChatParticipantTextMessageReceived(String userUsername, InetAddress userINETAddress, int port, String textMessage) {
		this.textMessageLog("A NEW MESSAGE FROM A PARTICIPANT:\n- " + userUsername
				            + " @ " + userINETAddress.getHostName() + " said: " + textMessage);
	} 
		
	/**
	 * Command-line invocation of the (Secure) Multicast Chat's application, expecting:
	 * - At least, 3 arguments [<Nickname or Username> <IP Multicast Group> <Port>]
	 * - At most, 4 arguments [<Nickname or Username> <IP Multicast Group> <Port> { <Time To Live (T.T.L.)> }]
	 * 
	 * @param args the arguments to be used during the initialization of the (Secure) Multicast Chat's application
	 */
	public static void main(String[] args) {
		
		// Error during the usage of the arguments, during the command-line invocation
		if((args.length != 3) && (args.length != 4)) {
			System.err.println("Usage: MulticastChatClient " 
							   + "<Nickname or Username> <IP Multicast Group> <Port> { <Time To Live (T.T.L.)> }");
			System.err.println("       - Default Time To Live (T.T.L.) = 1");
			
			// Exits and closes the (Secure) Multicast Chat's application
			System.exit(1);
		} 
		
		
		// The Username of the User (Client)
		String userUsername = args[0];
		
		// The INET Address of the IP (Secure) Multicast Group
		InetAddress ipMulticastGroup = null;
		
		// The Port used by the (Secure) Multicast Chat Socket
		int port = -1;
		
		// The T.T.L. (Time To Live) to be used by the (Secure) Multicast Chat's Session 
		int timeToLive = 1;
		
		
		// Retrieves the INET Address of the IP (Secure) Multicast Group
		try {
			ipMulticastGroup = InetAddress.getByName(args[1]);
		}
		catch (Throwable throwableException) {
			System.err.println("The IP (Secure) Multicast Group Address it's invalid: " 
							   + throwableException.getMessage() + "!!!");
			
			// Exits and closes the (Secure) Multicast Chat's application
			System.exit(1);
		} 
		
		// The INET Address of the IP (Secure) Multicast Group it's not an IP Multicast Address 
		if (!ipMulticastGroup.isMulticastAddress()) {
			System.err.println("The argument for the The IP (Secure) Multicast Group Address '" + args[1] 
							   + "' it's not an IP Multicast Address!!!");
			
			// Exits and closes the (Secure) Multicast Chat's application
			System.exit(1);
		} 
		
		// Retrieves the Port used by the (Secure) Multicast Chat Socket
		try {
			port = Integer.parseInt(args[2]);
		}
		catch (NumberFormatException numberFormatException) {
			System.err.println("Invalid Port: " + args[2]);
			
			// Exits and closes the (Secure) Multicast Chat's application
			System.exit(1);
		} 
		
		// The T.T.L. (Time To Live) was also defined by the User (Client)
		if (args.length >= 4) {
			try {
				timeToLive = Integer.parseInt(args[3]);
			}
			catch (NumberFormatException numberFormatException) {
				System.err.println("Invalid T.T.L. (Time To Live): " + args[3]);
			
				// Exits and closes the (Secure) Multicast Chat's application
				System.exit(1); 
			} 
		} 

		try {
			// Creates the (Secure) Multicast Chat's Session
			MulticastChatClient secureMulticastChatClient = new MulticastChatClient();
			
			// Sets the dimensions of the Frame/Window of the (Secure) Multicast Chat's Session
			secureMulticastChatClient.setSize(CommonUtils.FRAME_WINDOW_SECURE_MULTICAST_CHAT_WIDTH,
						  								 CommonUtils.FRAME_WINDOW_SECURE_MULTICAST_CHAT_HEIGHT);
			
			// Sets the Frame/Window of the (Secure) Multicast Chat,
			// previously defined, as visible
			secureMulticastChatClient.setVisible(true);
			
			// Performs the JOIN Message Operation by the User (Client) on the (Secure) Multicast Chat's Session
			secureMulticastChatClient.joinOperationToTheMulticastChatSession(userUsername, ipMulticastGroup, port, timeToLive);
		}
		catch (Throwable throwableException) {
			
			// Prints/Shows a message if an Error occurred
			// when initializing the Frame/Window of the (Secure) Multicast Chat
			System.err.println("Error occurred when initializing the Frame/Window of the (Secure) Multicast Chat: "
							   + throwableException.getClass().getName() + ": " + throwableException.getMessage());
			
			// Exits and closes the (Secure) Multicast Chat's application
			System.exit(1);
		} 
	} 
	
}