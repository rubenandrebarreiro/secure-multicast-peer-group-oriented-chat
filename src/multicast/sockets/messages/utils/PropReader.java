package multicast.sockets.messages.utils;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.InvalidPropertiesFormatException;
import java.util.Properties;

public class PropReader {
	
	public static void main(String[] args) {
		PropReader prop = new PropReader("res/SMCP.conf");
		
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
	}
	
	Properties properties;
	
	public PropReader(String filename) {
		properties = new Properties();
		try {
			properties.load(new FileInputStream(filename));
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
