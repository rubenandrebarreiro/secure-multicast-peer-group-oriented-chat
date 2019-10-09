package multicast.sockets.messages.utils;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.InvalidPropertiesFormatException;
import java.util.Properties;

public class PropReader {
	
	public static void main(String[] args) {
		PropReader prop = new PropReader("Untitled 1");
		System.out.println(prop.getProperty("224.5.6.7:9000"));
		System.out.println(prop.getProperty("SID"));
		System.out.println(prop.getProperty("224.5.6.7:9000/SID"));
	}
	
	Properties properties;
	
	public PropReader(String filepath) {
		properties = new Properties();
		try {
			properties.load(getClass().getResourceAsStream(filepath));
		} catch (InvalidPropertiesFormatException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public String getProperty(String key) {
		return properties.getProperty(key);
	}
}
