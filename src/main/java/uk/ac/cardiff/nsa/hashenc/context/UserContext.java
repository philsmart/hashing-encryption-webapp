package uk.ac.cardiff.nsa.hashenc.context;

import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

/**
 * A context to store state specific to a user
 */
@Component("userContext")
@Scope("session")
public class UserContext {
	
	/** The current encryption message. */
	private String encMessage;

	/** The current encryption key. */
	private String encKey;

	/** The name of the chosen encryption script. */
	private String chosenEncFunction;
	
	public UserContext() {
		encMessage = "Text";
		encKey = "0";
		chosenEncFunction = "caesar-cipher";
	}

	public String getEncMessage() {
		return encMessage;
	}

	public void setEncMessage(String encMessage) {
		this.encMessage = encMessage;
	}

	public String getEncKey() {
		return encKey;
	}

	public void setEncKey(String encKey) {
		this.encKey = encKey;
	}

	public String getChosenEncFunction() {
		return chosenEncFunction;
	}

	public void setChosenEncFunction(String chosenEncFunction) {
		this.chosenEncFunction = chosenEncFunction;
	}
	

}
