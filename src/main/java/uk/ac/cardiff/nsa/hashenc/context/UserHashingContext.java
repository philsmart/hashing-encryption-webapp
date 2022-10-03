
package uk.ac.cardiff.nsa.hashenc.context;

import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

/**
 * A context to store state specific to a user
 * 
 * Threadsafe
 */
@Component("userHashingContext")
@Scope("session")
public class UserHashingContext {

    /** This script state is shared between all users of the application. */
    private String script;

    /**
     * Get the script
     *
     * @return the script
     */
    public final synchronized String getScript() {
        return script;
    }

    /**
     * Set the script.
     *
     * @param script the script to set
     */
    public final synchronized void setScript(final String script) {
        this.script = script;
    }

}