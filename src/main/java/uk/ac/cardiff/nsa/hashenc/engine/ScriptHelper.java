package uk.ac.cardiff.nsa.hashenc.engine;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;

import javax.script.Invocable;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;

import org.springframework.core.io.Resource;
import org.springframework.util.FileCopyUtils;

public class ScriptHelper {
    
    public static Object runScript(final String script, final String message) throws ScriptException, NoSuchMethodException {
        final ScriptEngine engine = new ScriptEngineManager().getEngineByName("Nashorn");
        engine.eval(new StringReader(script));
        Invocable invocable = (Invocable) engine;

        return invocable.invokeFunction("hash", message);
        
    }
    
    public static String loadScriptResourceToString(final Resource scriptResource) {
    	try (Reader reader = new InputStreamReader(scriptResource.getInputStream(), StandardCharsets.UTF_8)) {
            return FileCopyUtils.copyToString(reader);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
    
    //FIXME no need for two methods here.
    public static Object runEncryptScript(final String varName, final String script, final Object... params) 
    		throws ScriptException, NoSuchMethodException {
        final ScriptEngine engine = new ScriptEngineManager().getEngineByName("Nashorn");
        engine.eval(new StringReader(script));
        Invocable invocable = (Invocable) engine;

        return invocable.invokeFunction(varName, params);
        
    }

}
