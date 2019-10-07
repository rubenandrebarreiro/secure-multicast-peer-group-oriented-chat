// MulticastChat.java
// Objecto que representa um chat Multicast

import java.io.*;
import java.net.*;
import java.util.*;

public class MulticastChat extends Thread {


  // Identifica uma op. de JOIN ao chat multicast  // 
  public static final int JOIN = 1;

  // Identifica uma op. de LEAVE do chat multicast  //    
  public static final int LEAVE = 2;

  // Identifica uma op. de processamento de uma MENSAGEM normal //       
  public static final int MESSAGE = 3;

  // N. Magico que funciona como Id unico do Chat 
  public static final long CHAT_MAGIC_NUMBER = 4969756929653643804L;

  // numero de milisegundos no teste de pooling de terminacao  // 
  public static final int DEFAULT_SOCKET_TIMEOUT_MILLIS = 5000;

  // Multicast socket used to send and receive multicast protocol PDUs
  // Socket Multicast usado para enviar e receber mensagens 
  // no ambito das operacoes que tem lugar no Chat
  protected MulticastSocket msocket;

  // Username / User-Nick-Name do Chat
  protected String username;

  // Grupo IP Multicast utilizado
  protected InetAddress group;

  // Listener de eventos enviados por Multicast
  protected MulticastChatEventListener listener;


  // Controlo  - thread de execucao

  protected boolean isActive;

  public MulticastChat(String username, InetAddress group, int port, 
                       int ttl, 
                       MulticastChatEventListener listener) throws IOException {

    this.username = username;
    this.group = group;
    this.listener = listener;
    isActive = true;

    // create & configure multicast socket
    msocket = new MulticastSocket(port);
    msocket.setSoTimeout(DEFAULT_SOCKET_TIMEOUT_MILLIS);
    msocket.setTimeToLive(ttl);
    msocket.joinGroup(group);

    // start receive thread and send multicast join message
    start();
    sendJoin();
  }

  /**
   * Request de terminacao assincrona da thread de execucao,
   * e envio de uma mensagem de LEAVE
   */

  public void terminate() throws IOException {
    isActive = false;
    sendLeave();
  } 

  // Issues an error message
  protected void error(String message) {
    System.err.println(new java.util.Date() + ": MulticastChat: " 
                       + message);
  } 

  // Envio de mensagem na op. de JOIN
  // 
  protected void sendJoin() throws IOException {
    ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
    DataOutputStream dataStream = new DataOutputStream(byteStream);

    dataStream.writeLong(CHAT_MAGIC_NUMBER);
    dataStream.writeInt(JOIN);
    dataStream.writeUTF(username);
    dataStream.close();

    byte[] data = byteStream.toByteArray();
    DatagramPacket packet = new DatagramPacket(data, data.length, group, 
                                               msocket.getLocalPort());
    msocket.send(packet);
  } 

  // Processamento de um JOIN ao grupo multicast com notificacao
  // 
  protected void processJoin(DataInputStream istream, InetAddress address, 
                             int port) throws IOException {
    String name = istream.readUTF();

    try {
      listener.chatParticipantJoined(name, address, port);
    } catch (Throwable e) {}
  } 

  // Envio de mensagem de LEAVE para o Chat
  protected void sendLeave() throws IOException {

    ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
    DataOutputStream dataStream = new DataOutputStream(byteStream);

    dataStream.writeLong(CHAT_MAGIC_NUMBER);
    dataStream.writeInt(LEAVE);
    dataStream.writeUTF(username);
    dataStream.close();

    byte[] data = byteStream.toByteArray();
    DatagramPacket packet = new DatagramPacket(data, data.length, group, 
                                               msocket.getLocalPort());
    msocket.send(packet);
  } 

  // Processes a multicast chat LEAVE PDU and notifies listeners
  // Processamento de mensagem de LEAVE  // 
  protected void processLeave(DataInputStream istream, InetAddress address, 
                              int port) throws IOException {
    String username = istream.readUTF();

    try {
      listener.chatParticipantLeft(username, address, port);
    } catch (Throwable e) {}
  } 

  // Envio de uma mensagem normal
  // 
  public void sendMessage(String message) throws IOException {

    ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
    DataOutputStream dataStream = new DataOutputStream(byteStream);

    dataStream.writeLong(CHAT_MAGIC_NUMBER);
    dataStream.writeInt(MESSAGE);
    dataStream.writeUTF(username);
    dataStream.writeUTF(message);
    dataStream.close();

    byte[] data = byteStream.toByteArray();
    DatagramPacket packet = new DatagramPacket(data, data.length, group, 
                                               msocket.getLocalPort());
    msocket.send(packet);
  } 


  // Processamento de uma mensagem normal  //
  // 
  protected void processMessage(DataInputStream istream, 
                                InetAddress address, 
                                int port) throws IOException {
    String username = istream.readUTF();
    String message = istream.readUTF();

    try {
      listener.chatMessageReceived(username, address, port, message);
    } catch (Throwable e) {}
  } 

  // Loops - recepcao e desmultiplexagem de datagramas de acordo com
  // as operacoes e mensagens
  // 
  public void run() {
    byte[] buffer = new byte[65508];
    DatagramPacket packet = new DatagramPacket(buffer, buffer.length);

    while (isActive) {
      try {

        // Comprimento do DatagramPacket RESET antes do request
        packet.setLength(buffer.length);
        msocket.receive(packet);

        DataInputStream istream = 
          new DataInputStream(new ByteArrayInputStream(packet.getData(), 
                packet.getOffset(), packet.getLength()));

        long magic = istream.readLong();

        if (magic != CHAT_MAGIC_NUMBER) {
          continue;

        } 
        int opCode = istream.readInt();
        switch (opCode) {
        case JOIN:
          processJoin(istream, packet.getAddress(), packet.getPort());
          break;
        case LEAVE:
          processLeave(istream, packet.getAddress(), packet.getPort());
          break;
        case MESSAGE:
          processMessage(istream, packet.getAddress(), packet.getPort());
          break;
        default:
          error("Cod de operacao desconhecido " + opCode + " enviado de " 
                + packet.getAddress() + ":" + packet.getPort());
        }

      } catch (InterruptedIOException e) {

        /**
         * O timeout e usado apenas para forcar um loopback e testar
		 * o valor isActive 
         */
	 
	 
      } catch (Throwable e) {
        error("Processing error: " + e.getClass().getName() + ": " 
              + e.getMessage());
      } 
    } 

    try {
      msocket.close();
    } catch (Throwable e) {}
  } 
}
