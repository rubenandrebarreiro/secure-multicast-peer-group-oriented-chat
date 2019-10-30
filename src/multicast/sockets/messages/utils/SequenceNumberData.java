package multicast.sockets.messages.utils;

public class SequenceNumberData {

	private int sequenceNumber;
	
	private long timestamp;
	
	public SequenceNumberData(int sequenceNumber, long timestamp) {
		this.sequenceNumber = sequenceNumber;
		this.timestamp = timestamp;
	}
	
	public void updateSequenceNumber(int sequenceNumber, long timestamp) {
		this.sequenceNumber = sequenceNumber;
		this.timestamp = timestamp;
	}
	
	public int getSequenceNumber() {
		return sequenceNumber;
	}
	
	public long getTimestamp() {
		return timestamp;
	}
	
}
