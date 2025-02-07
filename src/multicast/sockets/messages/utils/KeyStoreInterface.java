package multicast.sockets.messages.utils;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * 
 * Class to read, modify and save keystores.
 * 
 * @supervisor Prof. Henrique Joao Domingos - hj@fct.unl.pt
 * 
 * @author Eduardo Bras Silva (no. 41798) - emf.silva@campus.fct.unl.pt
 * @author Ruben Andre Barreiro (no. 42648) - r.barreiro@campus.fct.unl.pt
 *
 */
public class KeyStoreInterface {

	KeyStore ks;
	FileInputStream fis;
	BufferedReader br;
	String filename;
	String password;
    KeyStore.ProtectionParameter protParam;
	
	public KeyStoreInterface() {
		ks = null;
		fis = null;
		protParam = null;
		br = new BufferedReader(new InputStreamReader(System.in));
		String line = null;
		String[] split;
		help();
		try {
			while( !(line = br.readLine()).equals("exit") ) {
				switch (line) {
				case "open":
					System.out.println("<filename> <password>");
					split = br.readLine().split(" ");
					filename = split[0];
					password = split[1];
					open(filename, password.toCharArray());
					break;
				case "load":
					if(ks != null) {
						System.out.println("<keyName>");
						System.out.println("Key " + load(br.readLine()));
					} else System.out.println("Open keystore first");
					break;
				case "save":
					if(ks != null) {
						System.out.println("<keyName> <key>");
						split = br.readLine().split(" ");
						save(split[0], split[1]);
					} else System.out.println("Open keystore first");
					break;
				case "delete":
					if(ks != null) {
						System.out.println("<keyName>");
						delete(br.readLine());
					} else System.out.println("Open keystore first");
					break;
				case "list":
					if(ks != null) {
						list();
					} else System.out.println("Open keystore first");
					break;
				default:
					help();
					break;
				}
			}
			close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	// Constructors:
	/**
	 * Constructor #1:
	 * 
	 * Creates an interface for a keystore
	 * 
	 * @param filename file path of the keystore
	 * @param password password of the keystore
	 */
	public KeyStoreInterface(String filename, String password) {
		open(filename, password.toCharArray());
	}
	
	public static void main(String[] args) {
		new KeyStoreInterface();
	}
	
	/**
	 * Opens a keystore
	 * @param filename file path of the keystore
	 * @param password 
	 */
	public void open(String filename, char[] password) {
		try {
			ks = KeyStore.getInstance("JCEKS");
	        fis = new FileInputStream(filename);
	        ks.load(fis, password);
			protParam = new KeyStore.PasswordProtection(password);
			this.filename = filename;
			this.password = new String(password);
		} catch (Exception e) {
			// TODO: handle exception
			ks = null;
			System.err.println("Something happened, could not open keystore!");
		}

	}
	
	/**
	 * Loads a keystore entry
	 * @param entry name to load
	 * @return value associated with entry
	 */
	public  String load(String entry) {
	    KeyStore.SecretKeyEntry pkEntry = null;
		try {
			pkEntry = (KeyStore.SecretKeyEntry)
			        ks.getEntry(entry, protParam);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnrecoverableEntryException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		SecretKey mySecretKey = null;
		String encodedKey = "";
		try {
	        mySecretKey = pkEntry.getSecretKey();
	        encodedKey = Base64.getEncoder().encodeToString(mySecretKey.getEncoded());
		} catch (Exception e) {
			System.err.println("No key with alias " + entry);
		}
	        // get base64 encoded version of the key
	        return encodedKey;
	}
	
	/**
	 * Stores a key associated with a name
	 * @param alias name of the key
	 * @param key the key string
	 */
	public void save(String alias, String key) {
		byte[] decodedKey = Base64.getDecoder().decode(key);
		SecretKey mySecretKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES"); 
	    KeyStore.SecretKeyEntry skEntry =
	        new KeyStore.SecretKeyEntry(mySecretKey);
	    try {
			ks.setEntry(alias, skEntry, protParam);
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	/**
	 * Closes keystore
	 */
	public void close() {
		if(ks != null) {
		    FileOutputStream fos = null;
		    try {
		        try {
					fos = new FileOutputStream(filename);
				} catch (FileNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
		        ks.store(fos, password.toCharArray());
		    } catch (KeyStoreException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (CertificateException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} finally {
		        if (fos != null) {
		            try {
						fos.close();
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
		        }
		    }
		}
	}
	
	/**
	 * Deletes entry from keystore
	 * @param alias entry to delete from keystore
	 */
	public void delete(String alias) {
		try {
			ks.deleteEntry(alias);
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	

	/**
	 * Lists all key-values on keystore
	 */
	public void list() {
        Enumeration<String> enumeration = null;
		try {
			enumeration = ks.aliases();
	        List<String> list = Collections.list(enumeration);
	        Collections.sort(list);
	        for (String alias : list) {
				System.out.println(alias + " " + load(alias));
			}
	        } catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	private void help() {
		System.out.println("open <enter> <filename> <password>: opens keystore with given name and password");
		System.out.println("load <enter> <keyName>: loads key");
		System.out.println("save <enter> <keyName> <key>: saves key with name keyname");
		System.out.println("delete <enter> <keyName>: deletes key with alias keyName from keystore");
		System.out.println("list: lists all SecretKey stored in Keystore");
		System.out.println("exit: exits this interface");
		System.out.println("Giving any other command will display this help");
	}
}
