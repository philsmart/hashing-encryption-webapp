
package uk.ac.cardiff.nsa.hashenc.context;

import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

/**
 * A context to store state specific to a user
 * 
 * Threadsafe
 */
@Component("UserDigitalSignatureContext")
@Scope("session")
public class UserDigitalSignatureContext {

    private String payload;
    
    private String key;
    
    /** The JOSE header.*/
    private String header;
    
    private byte[] signature;

	/**
	 * Get the payload.
	 *
	 * @return the payload
	 */
	public synchronized String getPayload() {
		return payload;
	}

	/**
	 * Set the payload.
	 *
	 * @param payload the payload to set
	 */
	public synchronized void setPayload(String payload) {
		this.payload = payload;
	}

	/**
	 * Get the key.
	 *
	 * @return the key
	 */
	public synchronized String getKey() {
		return key;
	}

	/**
	 * Set the key.
	 *
	 * @param key the key to set
	 */
	public synchronized void setKey(String key) {
		this.key = key;
	}

	/**
	 * Get the header.
	 *
	 * @return the header
	 */
	public synchronized String getHeader() {
		return header;
	}

	/**
	 * Set the header.
	 *
	 * @param header the header to set
	 */
	public synchronized void setHeader(String header) {
		this.header = header;
	}

	/**
	 * Get the signature.
	 *
	 * @return the signature
	 */
	public synchronized byte[] getSignature() {
		return signature;
	}

	/**
	 * Set the signature.
	 *
	 * @param signature the signature to set
	 */
	public synchronized void setSignature(byte[] signature) {
		this.signature = signature;
	}
    
    

}