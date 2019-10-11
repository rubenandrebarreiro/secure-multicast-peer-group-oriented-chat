package multicast.sockets.services;

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

import java.util.Map;
import java.util.Map.Entry;

import multicast.common.CommonUtils;

/**
 * 
 * Class for the Cleaning Random Nonces' Services of the Secure Multicast Socket.
 * 
 * @supervisor Prof. Henrique Joao Domingos - hj@fct.unl.pt
 * 
 * @author Eduardo Bras Silva (no. 41798) - emf.silva@campus.fct.unl.pt
 * @author Ruben Andre Barreiro (no. 42648) - r.barreiro@campus.fct.unl.pt
 *
 */
public class SecureMulticastSocketCleaningRandomNoncesService implements Runnable {
	
	// Global Instance Variables:
	/**
	 * The Random Nonces' Map, where will be kept the current valid Nonces of the Secure Multicast Socket
	 */
	private Map<Integer, Long> randomNoncesMap;
	
	
	
	// Constructors:
	/**
	 * Constructor #1:
	 * - Constructor of the Cleaning/Removing Random Nonces Service,
	 *   responsible for cleaning/removing old previous invalid Random Nonces,
	 *   after 10 seconds (10000 milliseconds) of being added to the Random Nonces' Map for the first time
	 * 
	 * @param randomNoncesMap the Random Nonces' Map,
	 *        where will be kept the current valid Random Nonces of the Secure Multicast Socket
	 */
	public SecureMulticastSocketCleaningRandomNoncesService(Map<Integer, Long> randomNoncesMap) {
		this.randomNoncesMap = randomNoncesMap;
	}
	
	
	
	// Methods:
	/**
	 * Runnable Thread Process of the Cleaning/Removing Random Nonces Service,
	 * responsible for cleaning/removing old previous invalid Random Nonces,
	 * after 10 seconds (10000 milliseconds) of being added to the Random Nonces' Map for the first time
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
		
			// Verification made for every Random Nonces currently in Random Nonces' Map
			for(Entry<Integer, Long> noncesTimestamps : this.randomNoncesMap.entrySet()) {
				long lastNonceReceivedTimestamp = noncesTimestamps.getValue();
				
				// The previous Random Nonces are valid for the last 10 minutes (600000 milliseconds),
				// after that, they will be removed from the Random Nonces' Map
				// Otherwise, they will be kept on the Random Nonces' Map for the remaining time,
				// until be reached the time equal or greater than 10 minutes (600000 milliseconds)
				if( (lastNonceReceivedTimestamp + CommonUtils.NONCES_CLEANING_TIMEOUT) < System.currentTimeMillis() ) {
					this.randomNoncesMap.remove(noncesTimestamps.getKey());
				}
			}
		}
	}
}