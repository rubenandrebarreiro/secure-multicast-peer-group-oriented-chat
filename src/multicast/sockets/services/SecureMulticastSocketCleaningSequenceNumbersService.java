package multicast.sockets.services;

import java.util.Map.Entry;
import java.util.concurrent.ConcurrentMap;

import multicast.common.CommonUtils;
import multicast.sockets.messages.utils.SequenceNumberData;

public class SecureMulticastSocketCleaningSequenceNumbersService implements Runnable {

	// Global Instance Variables:
	/**
	 * The Sequence Number Map, where will be kept the current sequence numbers of the Secure Multicast Socket
	 */
	private ConcurrentMap<String, SequenceNumberData> sequenceNumberMap;
	
	
	
	// Constructors:
	/**
	 * Constructor #1:
	 * - Constructor of the Sequence Number cleaning Service,
	 *   responsible for removing old sequence numbers,
	 *   after 10 seconds (10000 milliseconds) of the last time the 
	 *   sequence number was updated.
	 * 
	 * @param randomNoncesMap the Random Nonces' Map,
	 *        where will be kept the current valid Random Nonces of the Secure Multicast Socket
	 */
	public SecureMulticastSocketCleaningSequenceNumbersService(ConcurrentMap<String, SequenceNumberData> sequenceNumberMap) {
		this.sequenceNumberMap = sequenceNumberMap;
	}
	
	// Methods:
	/**
	 * Runnable Thread Process of the Sequence Number cleaning Service,
	 * responsible for removing old sequence numbers,
	 * after 10 seconds (10000 milliseconds) of the last time the 
	 * sequence number was updated.
	 */
	@Override
	public void run() {
		for(;;) {
			try {
				// Sleeping for each 10 seconds (10000 milliseconds)
				Thread.sleep(CommonUtils.CLEANING_SEQUENCE_NUMBERS_SERVICE_VERIFICATION_RATE_TIME);
			}
			catch (InterruptedException interruptedException) {
				System.err.println("Error occurred during the Service of Cleaning Nonces on the Secure Multicast Socket:");
				System.err.println("- Runnable Thread process interrupted!!!");
				interruptedException.printStackTrace();
			}
			
			// Verification made for every sequence number currently in sequence numbers' Map
			for(Entry<String, SequenceNumberData> sequenceTimestamp : this.sequenceNumberMap.entrySet()) {
				long lastSequenceReceivedTimestamp = sequenceTimestamp.getValue().getTimestamp();
				// The previous sequence numbers are valid for the last 10 minutes (600000 milliseconds),
				// after that, they will be removed from the sequence numbers' Map
				// Otherwise, they will be kept on the sequence numbers' Map for the remaining time,
				// until be reached the time equal or greater than 10 minutes (600000 milliseconds)
				System.out.println("[" + this.getClass().getCanonicalName() + "]: " + "checking: " + sequenceTimestamp.getKey());
				long systemTime = System.currentTimeMillis();
				System.out.println("[" + this.getClass().getCanonicalName() + "]: " +
						"checking: " + (lastSequenceReceivedTimestamp + CommonUtils.SEQUENCE_NUMBERS_CLEANING_TIMEOUT) + " < " + systemTime +
						" and the result is: " + ((lastSequenceReceivedTimestamp + CommonUtils.SEQUENCE_NUMBERS_CLEANING_TIMEOUT) < systemTime));
				if( (lastSequenceReceivedTimestamp + CommonUtils.SEQUENCE_NUMBERS_CLEANING_TIMEOUT) < systemTime ) {
					System.out.println("[" + this.getClass().getCanonicalName() + "]: " + "Removing sequenceNumber of " + sequenceTimestamp.getKey());
					this.sequenceNumberMap.remove(sequenceTimestamp.getKey());
				}
			}
		}
	}

}
