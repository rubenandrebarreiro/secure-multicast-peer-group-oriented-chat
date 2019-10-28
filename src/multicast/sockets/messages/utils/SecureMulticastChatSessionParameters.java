package multicast.sockets.messages.utils;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * 
 * Class to read properties file.
 * 
 * @supervisor Prof. Henrique Joao Domingos - hj@fct.unl.pt
 * 
 * @author Eduardo Bras Silva (no. 41798) - emf.silva@campus.fct.unl.pt
 * @author Ruben Andre Barreiro (no. 42648) - r.barreiro@campus.fct.unl.pt
 *
 */
public class SecureMulticastChatSessionParameters {

	public static void main(String[] args) {
		SecureMulticastChatSessionParameters prop = new SecureMulticastChatSessionParameters("res/SMCP.conf","224.5.6.7:9000");

		System.out.println(prop.getProperty("ip"));
		System.out.println(prop.getProperty("port"));
		System.out.println(prop.getProperty("sid"));
		System.out.println(prop.getProperty("sea"));
		System.out.println(prop.getProperty("seaks"));
		System.out.println(prop.getProperty("mode"));
		System.out.println(prop.getProperty("padding"));
		System.out.println(prop.getProperty("inthash"));
		System.out.println(prop.getProperty("mac"));
		System.out.println(prop.getProperty("macks"));
		
		System.out.println();
		System.out.println("Changed sessionID ");
		prop.setSessionID("230.100.100.100:6666");
		System.out.println();
		
		System.out.println(prop.getProperty("ip"));
		System.out.println(prop.getProperty("port"));
		System.out.println(prop.getProperty("sid"));
		System.out.println(prop.getProperty("sea"));
		System.out.println(prop.getProperty("seaks"));
		System.out.println(prop.getProperty("mode"));
		System.out.println(prop.getProperty("padding"));
		System.out.println(prop.getProperty("inthash"));
		System.out.println(prop.getProperty("mac"));
		System.out.println(prop.getProperty("macks"));
		
		//Backwards compatible test
		System.out.println();
		System.out.println("Started backwards compatible test");
		System.out.println();
		
		SecureMulticastChatSessionParameters backwardsProp = new SecureMulticastChatSessionParameters("res/SMCP.conf");
		
		System.out.println(backwardsProp.getProperty("ip"));
		System.out.println(backwardsProp.getProperty("port"));
		System.out.println(backwardsProp.getProperty("sid"));
		System.out.println(backwardsProp.getProperty("sea"));
		System.out.println(backwardsProp.getProperty("seaks"));
		System.out.println(backwardsProp.getProperty("mode"));
		System.out.println(backwardsProp.getProperty("padding"));
		System.out.println(backwardsProp.getProperty("inthash"));
		System.out.println(backwardsProp.getProperty("mac"));
		System.out.println(backwardsProp.getProperty("macks"));
	}

	private Map<String, Map<String, String>> propertiesMap;
	private String currentSessionID;

	/**
	 * TODO THIS IS ABSOLUTELY TEMPORARY FOR COMPATIBILITY PURPOSES ONLY!!!
	 * @param filename
	 */
	public SecureMulticastChatSessionParameters(String filename) {
		this(filename, getSessionID(filename));
	}
	
	/**
	 * TODO THIS IS ABSOLUTELY TEMPORARY FOR COMPATIBILITY PURPOSES ONLY!!!
	 * @param br
	 * @throws IOException
	 */
	private static String getSessionID(String filename) {
		String sessionID = null;
		try {
			BufferedReader br = new BufferedReader(new FileReader(filename));
			sessionID = br.readLine();
			sessionID = String.valueOf(sessionID.subSequence(1, sessionID.length() - 1));
		}
		catch(Exception e) {
			System.err.println(e);
		}
		return sessionID;
	}
	
	/**
	 * Starts a reader for the SecureMulticastChatSessionParameters data.
	 * @param filename file to read from.
	 * @param sessionID session name to be used when getting properties.
	 */
	public SecureMulticastChatSessionParameters(String filename, String sessionID) {
		
		propertiesMap = new HashMap<>();
		currentSessionID = sessionID;
		
		BufferedReader br = null;
		try {
			String line;
			br = new BufferedReader(new FileReader(filename));
			do {
				readSessionID(br);
			} while( (line = br.readLine() ) != null);

			br.close();
			
		} catch (FileNotFoundException e) {
			printError("File not found!");
		} catch (IOException e) {
			printError("IOException!");
		}
	}

	/**
	 * Get saved property.
	 * @param key property to get.
	 * @return value from key.
	 */
	public String getProperty(String key) {
		return propertiesMap.get(currentSessionID).get(key);
	}

	/**
	 * Sets a new session name to be used when getting properties.
	 * @param sessionID session name to be used when getting properties.
	 */
	public void setSessionID(String sessionID) {
		currentSessionID = sessionID;
	}
	
	/**
	 * Prints an error with this class name for identification purposes.
	 * @param message message to print as error.
	 */
	private void printError(String message) {
		System.err.println("[" + this.getClass().getCanonicalName() + "]: " + message);
	}
	
	/**
	 * Read every sessionID available in a file.
	 * @param br bufferedReader already initialized with a file
	 * @throws IOException
	 */
	private void readSessionID(BufferedReader br) throws IOException {
		String sessionID = br.readLine();
//		System.out.println("1st sessionID = " + sessionID);
		sessionID = String.valueOf(sessionID.subSequence(1, sessionID.length() - 1));
//		System.out.println("2nd sessionID = " + sessionID);
		String[] split = sessionID.split(":");
		
//		for (String string : split) {
//			System.out.println(string);
//		}
		
		String ip = split[0];
		String port = split[1];
		
//		System.out.println(ip + " : " +  port);
		
		propertiesMap.put(sessionID, new HashMap<>());
		propertiesMap.get(sessionID).put("ip", ip);
		propertiesMap.get(sessionID).put("port", port);
		
		readSessionIDProperties(br, ip, propertiesMap.get(sessionID));
	}
	
	/**
	 * Read all session properties of a given sessionID.
	 * @param br bufferedReader already initialized with a file.
	 * @param sessionID sessionID for the properties to be saved to.
	 * @param sessionProperties Map where to save the session properties.
	 * @throws IOException
	 */
	private void readSessionIDProperties(BufferedReader br, String sessionID , Map<String, String> sessionProperties) throws IOException {
		String stopString = "</" + sessionID + ">";
		
//		System.out.println("Stop string is = " + stopString);
		String line = null;
		String propertyKey, propertyValue;
		int indexEndOfFirstPropertyName, indexStartOfSecondPropertyName;
//		System.out.println("Property Key -> Property Value");
		while( !(line = br.readLine().trim()).equals(stopString) ) {
			indexEndOfFirstPropertyName = line.indexOf(">");
			indexStartOfSecondPropertyName = line.indexOf("<", indexEndOfFirstPropertyName);
			propertyKey = line.substring(1, indexEndOfFirstPropertyName).toLowerCase();
			propertyValue = line.substring(indexEndOfFirstPropertyName + 1, indexStartOfSecondPropertyName);
//			System.out.println(propertyKey + " -> " + propertyValue);
			sessionProperties.put(propertyKey, propertyValue);
		}
	}
}
