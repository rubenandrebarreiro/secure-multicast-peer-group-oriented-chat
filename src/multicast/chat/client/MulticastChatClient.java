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
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.text.*;

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
	protected JTextField messageField;
	
	/**
	 * The JTextField for the text field, which can be entered a file to download
	 */
	protected JTextField fileField;
	
	/**
	 * The Default List Model containing all the online Users
	 * currently online in the (Secure) Multicast Chat
	 */
	protected DefaultListModel<String> onlineUsersList;
	
	
	// Constructors:
	/**
	 * Disconnected
	 */
	
	// Construtor para uma frame com do chat multicast  (inicializado em estado nao conectado)
	public MulticastChatClient() {
		super("(Secure) Multicast Chat (Mode: Disconnected)");

		// Construct GUI components (iniciaizacao de sessao)
		// Builds the several components of the Graphic User Interface (G.U.I.),
		// related to the (Secure) Multicast Chat for the initializing of
		// the Chat's Session
		conversationMulticastChatTextArea = new JTextArea();
		conversationMulticastChatTextArea.setEditable(false);
		conversationMulticastChatTextArea.setLineWrap( true);
		conversationMulticastChatTextArea.setBorder(BorderFactory.createLoweredBevelBorder());

		JScrollPane textAreaScrollPane = new JScrollPane(conversationMulticastChatTextArea, 
														 JScrollPane.VERTICAL_SCROLLBAR_ALWAYS, 
														 JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
		getContentPane().add(textAreaScrollPane, BorderLayout.CENTER);
				
		onlineUsersList = new DefaultListModel();
		JList usersList = new JList( onlineUsersList);
		JScrollPane usersListScrollPane = new JScrollPane(usersList, 
														 JScrollPane.VERTICAL_SCROLLBAR_ALWAYS, 
														 JScrollPane.HORIZONTAL_SCROLLBAR_NEVER) {
				public Dimension getMinimumSize() {
					Dimension d = super.getMinimumSize();
					d.width = 100;
					return d;
				}
				public Dimension getPreferredSize() {
					Dimension d = super.getPreferredSize();
					d.width = 100;
					return d;
				}
			};
		getContentPane().add(usersListScrollPane, BorderLayout.WEST);

		Box box = new Box( BoxLayout.Y_AXIS);
		box.add( Box.createVerticalGlue());
		JPanel messagePanel = new JPanel(new BorderLayout());

		messagePanel.add(new JLabel("Menssagem:"), BorderLayout.WEST);

		messageField = new JTextField();
		messageField.addActionListener( new ActionListener() {
			public void actionPerformed(ActionEvent e) {
			sendMessage();
			}
			});
		messagePanel.add(messageField, BorderLayout.CENTER);

		JButton sendButton = new JButton("  ENVIAR ");
		sendButton.addActionListener( new ActionListener() {
			public void actionPerformed(ActionEvent e) {
			sendMessage();
			}
			});
		messagePanel.add(sendButton, BorderLayout.EAST);
		box.add( messagePanel);

		box.add( Box.createVerticalGlue());
		
		
		JPanel filePanel = new JPanel(new BorderLayout());

		filePanel.add(new JLabel("Not used"), BorderLayout.WEST);
		fileField = new JTextField();
		fileField.addActionListener( new ActionListener() {
			public void actionPerformed(ActionEvent e) {
			downloadFile();
			}
			});
		filePanel.add(fileField, BorderLayout.CENTER);

		JButton downloadButton = new JButton("Not Impl.");
		downloadButton.addActionListener( new ActionListener() {
		public void actionPerformed(ActionEvent e) {
		downloadFile();
		}
		});
		filePanel.add(downloadButton, BorderLayout.EAST);
		box.add( filePanel);
		
		box.add( Box.createVerticalGlue());
		

		getContentPane().add(box, BorderLayout.SOUTH);

		// detect window closing and terminate multicast chat session
		// detectar o fecho da janela no termino de uma sessao de chat    // 
		addWindowListener( new WindowAdapter() {
			// Invocado na primeira vez que a janela e tornada visivel.
			public void windowOpened(WindowEvent e) {
				messageField.requestFocus();
			} 
			// terminar o char a quando do fecho da janela
			public void windowClosing(WindowEvent e) {
				onQuit();
				dispose();
			} 
			public void windowClosed(WindowEvent e) {
				System.exit(0);
			} 
			});
	}
	
	/**
	 * Adiciona utilizador no interface do utilizador
	 */
	protected void uiAddUser( String username) {
		onlineUsersList.addElement( username);
	}
	
	/**
	 * Remove utilizador no interface do utilizador.
	 * @return Devolve true se utilizador foi removido.
	 */
	protected boolean uiRemUser( String username) {
		return onlineUsersList.removeElement(username);
	}
	
	/**
	 * Inicializa lista de utilizadores a partir de um iterador -- pode ser usado
	 * obtendo iterador de qualquer estrutura de dados de java
	 */
	protected void uiInitUsers(Iterator<String> it) {
		onlineUsersList.clear();
		
		if(it != null) {
			while(it.hasNext()) {
				onlineUsersList.addElement(it.next());
			}
		}
	}
	
	/**
	 * Devolve um Enumeration com o nome dos utilizadores que aparecem no UI.
	 */
	protected Enumeration uiListUsers() {
		return onlineUsersList.elements();
	}
	
	// Configuracao do grupo multicast da sessao de chat na interface do cliente
	public void join(String username, InetAddress group, int port, 
					 int ttl) throws IOException {
		setTitle("CHAT MulticastIP " + username + "@" + group.getHostAddress() 
				 + ":" + port + " [TTL=" + ttl + "]");
		
		// Criar sessao de chat multicast
		multicastChat = new MulticastChat(username, group, port, ttl, this);
	} 

	protected void log(final String message) {
		java.util.Date date = new java.util.Date();

		SwingUtilities.invokeLater(new Runnable() {
			public void run() {
			conversationMulticastChatTextArea.append(message + "\n");
			} 
			});
	} 

	/**
	 * Envia mensagem. Chamado quando se carrega no botao de SEND ou se faz ENTER 
	 * na linha da mensagem. 
	 * Executa operacoes relacionadas com interface -- nao modificar
	 */
	protected void sendMessage() {
		String message = messageField.getText();
		messageField.setText("");
		doSendMessage( message);
		messageField.requestFocus();
	}

	/**
	 * Executa operacoes relativas ao envio de mensagens
	 */
	protected void doSendMessage( String message) {
		try {
			multicastChat.sendMessage(message);
		} catch (Throwable ex) {
			JOptionPane.showMessageDialog(this,
										  "Erro ao enviar uma menssagem: " 
										  + ex.getMessage(), "Chat Error", 
															 JOptionPane.ERROR_MESSAGE);
		} 
	}
	
	
	/**
	 * Imprime mensagem de erro
	 */
	protected void displayMsg( final String str, final boolean error) {
		final JFrame f = this;

		SwingUtilities.invokeLater(new Runnable() {
			public void run() {
				if( error)
					JOptionPane.showMessageDialog(f, str, "Chat Error", JOptionPane.ERROR_MESSAGE);
				else
					JOptionPane.showMessageDialog(f, str, "Chat Information", JOptionPane.INFORMATION_MESSAGE);
			} 
			});
	}

	/**
	 * Pede downlaod dum ficheiro. Chamado quando se carrega no botao de SEND ou se faz ENTER 
	 * na linha de download. 
	 * Executa operacoes relacionadas com interface -- nao modificar
	 */
	protected void downloadFile() {
		final String file = fileField.getText();
		fileField.setText("");
		new Thread( new Runnable() {
			public void run() {
				doDownloadFile( file);
			}
			}).start();
		messageField.requestFocus();
	}

	/**
	 * Executa operacoes relativas ao envio de mensagens.
	 * 
	 * NOTA: Qualquer informacao ao utilizador deve ser efectuada usando 
	 * o metodo "displayMsg".
	 */
	protected void doDownloadFile( String file) {
		// TODO: a completar
		System.err.println( "Pedido download do ficheiro " + file);
	}

	/**
	 * Chamado quando o utilizador fechou a janela do chat
	 */
	protected void onQuit() {
		try {
			if (multicastChat != null) {
				multicastChat.terminate();
			} 
		} catch (Throwable ex) {
			JOptionPane.showMessageDialog(this, "Erro no termino do chat:  "
										  + ex.getMessage(), "ERRO no Chat", 
										 JOptionPane.ERROR_MESSAGE);
		} 
	} 


	// Invocado quando s erecebe uma mensagem  // 
	public void secureMulticastChatParticipantTextMessageReceived(String username, InetAddress address, 
									int port, String message) {
		log("MSG:[" + username+"@"+address.getHostName() + "] disse: " + message);
	} 


	// Invocado quando um novo utilizador se juntou ao chat  // 
	public void secureMulticastChatParticipantJoined(String username, InetAddress address, 
									  int port) {
		log("+++ NOVO PARTICIPANTE: " + username + " juntou-se ao grupo do chat a partir de " + address.getHostName()
			+ ":" + port);
	} 

	// Invocado quando um utilizador sai do chat  // 
	public void secureMulticastChatParticipantLeft(String username, InetAddress address, 
									int port) {
		log("--- ABANDONO: " + username + " abandonou o grupo de chat, a partir de " + address.getHostName() + ":" 
			+ port);
	} 

	// Command-line invocation expecting three arguments
	public static void main(String[] args) {
		if ((args.length != 3) && (args.length != 4)) {
			System.err.println("Utilizar: MChatCliente " 
							   + "<nickusername> <grupo IPMulticast> <porto> { <ttl> }");
			System.err.println("       - TTL default = 1");
			System.exit(1);
		} 

		String username = args[0];
		InetAddress group = null;
		int port = -1;
		int ttl = 1;

		try {
			group = InetAddress.getByName(args[1]);
		}
		catch (Throwable throwableException) {
			System.err.println("The IP (Secure) Multicast Group Address it's invalid: " 
							   + throwableException.getMessage() + "!!!");
			System.exit(1);
		} 

		if (!group.isMulticastAddress()) {
			System.err.println("The Argument for the The IP (Secure) Multicast Group Address '" + args[1] 
							   + "' it's not an IP Multicast Address!!!");
			System.exit(1);
		} 

		try {
			port = Integer.parseInt(args[2]);
		}
		catch (NumberFormatException e) {
			System.err.println("Porto invalido: " + args[2]);
			System.exit(1);
		} 

		if (args.length >= 4) {
		
			try {
				ttl = Integer.parseInt(args[3]);
			} catch (NumberFormatException e) {
				System.err.println("TTL invalido: " + args[3]);
				System.exit(1); 
			} 
		} 

		try {
			
			
			MulticastChatClient frameWindowSecureMulticastChatClient = new MulticastChatClient();
			
			// Sets the dimensions of the Frame/Window of the (Secure) Multicast Chat
			frameWindowSecureMulticastChatClient.setSize(CommonUtils.FRAME_WINDOW_SECURE_MULTICAST_CHAT_WIDTH,
						  								 CommonUtils.FRAME_WINDOW_SECURE_MULTICAST_CHAT_HEIGHT);
			
			// Sets the Frame/Window of the (Secure) Multicast Chat,
			// previously defined, as visible
			frameWindowSecureMulticastChatClient.setVisible(true);
			
			frameWindowSecureMulticastChatClient.join(username, group, port, ttl);
		}
		catch (Throwable throwableException) {
			
			// Prints/Shows a message if an Error occurred
			// when initializing the Frame/Window of the (Secure) Multicast Chat
			System.err.println("Error occurred when initializing the Frame/Window of the (Secure) Multicast Chat: "
							   + throwableException.getClass().getName() + ": " + throwableException.getMessage());
			
			// Exits and closes the (Secure) Multicast Chat's Application
			System.exit(1);
		} 
	} 
}