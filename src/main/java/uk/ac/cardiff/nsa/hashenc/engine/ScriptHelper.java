package uk.ac.cardiff.nsa.hashenc.engine;

import java.io.StringReader;

import javax.script.Invocable;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;

public class ScriptHelper {
    
    public static Object runScript(final String script, final String message) throws ScriptException, NoSuchMethodException {
        
        final ScriptEngine engine = new ScriptEngineManager().getEngineByName("nashorn");
        engine.eval(new StringReader(script));
        Invocable invocable = (Invocable) engine;

        return invocable.invokeFunction("hash", message);
        
    }

}
