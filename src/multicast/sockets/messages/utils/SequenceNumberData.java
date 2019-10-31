package multicast.sockets.messages.utils;

/**
 * 
 * Class to store sequence numbers and their timestamps
 * 
 * @supervisor Prof. Henrique Joao Domingos - hj@fct.unl.pt
 * 
 * @author Eduardo Bras Silva (no. 41798) - emf.silva@campus.fct.unl.pt
 * @author Ruben Andre Barreiro (no. 42648) - r.barreiro@campus.fct.unl.pt
 *
 */
public class SequenceNumberData {

	/**
	 * Stores the sequence number
	 */
	private int sequenceNumber;
	
	/**
	 * Store the timestamp of then the 
	 * sequence number was received
	 */
	private long timestamp;
	
	// Constructors:
	/**
	 * Constructor #1:
	 * The constructor for a SequenceNumberData
	 * 
	 * @param sequenceNumber sequence number to save
	 * @param timestamp timestamp to save
	 * 
	 */
	public SequenceNumberData(int sequenceNumber, long timestamp) {
		this.sequenceNumber = sequenceNumber;
		this.timestamp = timestamp;
	}
	
	// Methods:
	/**
	 * Updates the sequence number and the timestamp
	 * @param sequenceNumber saves given sequence number
	 * @param timestamp saves given timestamp
	 */
	public void updateSequenceNumber(int sequenceNumber, long timestamp) {
		this.sequenceNumber = sequenceNumber;
		this.timestamp = timestamp;
	}
	
	/**
	 * Gets current sequence number
	 * @return current sequence number
	 */
	public int getSequenceNumber() {
		return sequenceNumber;
	}
	
	/**
	 * Gets current timestamp
	 * @return current timestamp
	 */
	public long getTimestamp() {
		return timestamp;
	}
	
}
