package multicast.sockets.services;

import java.util.Map;
import java.util.Map.Entry;

import multicast.common.CommonUtils;

public class SecureMulticastSocketCleaningNoncesService implements Runnable {
	
	// Global Instance Variables:

	/**
	 * The Nonces' Map, where will be kept the current valid Nonces of the Secure Multicast Socket
	 */
	private Map<Integer, Long> noncesMap;
	
	
	
	// Constructors:
	/**
	 * Constructor #1:
	 * - Constructor of the Cleaning/Removing Nonces Service, responsible for cleaning/removing old previous invalid Nonces,
	 *   after 10 seconds (10000 milliseconds) of being added to the Nonces' Map for the first time
	 * 
	 * @param noncesMap the Nonces' Map, where will be kept the current valid Nonces of the Secure Multicast Socket
	 */
	public SecureMulticastSocketCleaningNoncesService(Map<Integer, Long> noncesMap) {
		this.noncesMap = noncesMap;
	}
	
	
	
	// Methods:
	/**
	 * Runnable Thread Process of the Cleaning/Removing Nonces Service, responsible for cleaning/removing old previous invalid Nonces,
	 * after 10 seconds (10000 milliseconds) of being added to the Nonces' Map for the first time
	 */
	@Override
	public void run() {
		for(;;) {
			try {
				// Sleeping for each 10 seconds (10000 milliseconds)
				Thread.sleep(CommonUtils.CLEANING_NONCES_SERVICE_VERIFICATION_RATE_TIME);
			}
			catch (InterruptedException interruptedException) {
				System.err.println("Error occurred during the Service of Cleaning Nonces on the Secure Multicast Socket:");
				System.err.println("- Runnable Thread process interrupted!!!");
				interruptedException.printStackTrace();
			}
		
			// Verification made for every Nonces currently in Nonces' Map
			for(Entry<Integer, Long> noncesTimestamps : this.noncesMap.entrySet()) {
				long lastNonceReceivedTimestamp = noncesTimestamps.getValue();
				
				// The previous Nonces are valid for the last 10 minutes (600000 milliseconds),
				// after that, they will be removed from the Nonces' Map
				// Otherwise, they will be kept on the Nonces' Map for the remaining time,
				// until be reached the time equal or greater than 10 minutes (600000 milliseconds)
				if( (lastNonceReceivedTimestamp + CommonUtils.NONCES_CLEANING_TIMEOUT) < System.currentTimeMillis() ) {
					this.noncesMap.remove(noncesTimestamps.getKey());
				}
			}
		}
	}
}