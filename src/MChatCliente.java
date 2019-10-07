// MChatCliente.java
// 

import java.io.IOException;
import java.net.InetAddress;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.text.*;
import java.util.*;

// Interface para a sessao de chat swing-based
// e pode ir sendo melhorada pelos alunos para acomodar as
// diversas funcionalidades do trabalho 

public class MChatCliente extends JFrame implements MulticastChatEventListener
{
	// definicao de um objecto representando um "multicast chat"
	protected MulticastChat chat;

	// area de texto onde se mostram as mensagens das conversas ou a
	// mensagem qdo alguem se junta ao chat
	protected JTextArea textArea;

	// Campo de texto onde se dara a entrada de mensagens
	protected JTextField messageField;
	
	// Campo de texto onde se dara a entrada do ficheiro a fazer download
	protected JTextField fileField;
	
	// Lista com utilizadores no chat
	protected DefaultListModel users;

	// Construtor para uma frame com do chat multicast  (inicializado em estado nao conectado)
	public MChatCliente() {
		super("MulticastChat (modo: desconectado)");

		// Construct GUI components (iniciaizacao de sessao)
		textArea = new JTextArea();
		textArea.setEditable(false);
		textArea.setLineWrap( true);
		textArea.setBorder(BorderFactory.createLoweredBevelBorder());

		JScrollPane textAreaScrollPane = new JScrollPane(textArea, 
														 JScrollPane.VERTICAL_SCROLLBAR_ALWAYS, 
														 JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
		getContentPane().add(textAreaScrollPane, BorderLayout.CENTER);
		
		users = new DefaultListModel();
		JList usersList = new JList( users);
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
	protected void uiAddUser( String userName) {
		users.addElement( userName);
	}
	
	/**
	 * Remove utilizador no interface do utilizador.
	 * @return Devolve true se utilizador foi removido.
	 */
	protected boolean uiRemUser( String userName) {
		return users.removeElement( userName);
	}
	
	/**
	 * Inicializa lista de utilizadores a partir de um iterador -- pode ser usado
	 * obtendo iterador de qualquer estrutura de dados de java
	 */
	protected void uiInitUsers( Iterator it) {
		users.clear();
		if( it != null)
			while( it.hasNext()) {
				users.addElement( it.next());
			}
	}
	
	/**
	 * Devolve um Enumeration com o nome dos utilizadores que aparecem no UI.
	 */
	protected Enumeration uiListUsers() {
		return users.elements();
	}
	
	// Configuracao do grupo multicast da sessao de chat na interface do cliente
	public void join(String username, InetAddress group, int port, 
					 int ttl) throws IOException {
		setTitle("CHAT MulticastIP " + username + "@" + group.getHostAddress() 
				 + ":" + port + " [TTL=" + ttl + "]");


		
		// Criar sessao de chat multicast
		chat = new MulticastChat(username, group, port, ttl, this);
	} 

	protected void log(final String message) {
		java.util.Date date = new java.util.Date();

		SwingUtilities.invokeLater(new Runnable() {
			public void run() {
			textArea.append(message + "\n");
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
			chat.sendMessage(message);
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
			if (chat != null) {
				chat.terminate();
			} 
		} catch (Throwable ex) {
			JOptionPane.showMessageDialog(this, "Erro no termino do chat:  "
										  + ex.getMessage(), "ERRO no Chat", 
										 JOptionPane.ERROR_MESSAGE);
		} 
	} 


	// Invocado quando s erecebe uma mensagem  // 
	public void chatMessageReceived(String username, InetAddress address, 
									int port, String message) {
		log("MSG:[" + username+"@"+address.getHostName() + "] disse: " + message);
	} 


	// Invocado quando um novo utilizador se juntou ao chat  // 
	public void chatParticipantJoined(String username, InetAddress address, 
									  int port) {
		log("+++ NOVO PARTICIPANTE: " + username + " juntou-se ao grupo do chat a partir de " + address.getHostName()
			+ ":" + port);
	} 

	// Invocado quando um utilizador sai do chat  // 
	public void chatParticipantLeft(String username, InetAddress address, 
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
		} catch (Throwable e) {
			System.err.println("Endereco de grupo multicast invalido: " 
							   + e.getMessage());
			System.exit(1);
		} 

		if (!group.isMulticastAddress()) {
			System.err.println("Argumento Grupo '" + args[1] 
							   + "' nao e um end. IP multicast");
			System.exit(1);
		} 

		try {
			port = Integer.parseInt(args[2]);
		} catch (NumberFormatException e) {
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
			MChatCliente frame = new MChatCliente();
			frame.setSize(800, 300);
			frame.setVisible( true);

			frame.join(username, group, port, ttl);
		} catch (Throwable e) {
			System.err.println("Erro ao iniciar a frame: " + e.getClass().getName() 
							   + ": " + e.getMessage());
			System.exit(1);
		} 
	} 
}
