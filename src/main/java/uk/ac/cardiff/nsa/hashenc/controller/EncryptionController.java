package uk.ac.cardiff.nsa.hashenc.controller;

import javax.script.ScriptException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import uk.ac.cardiff.nsa.hashenc.engine.EncryptionEngine;
import uk.ac.cardiff.nsa.hashenc.engine.HashEngine;
import uk.ac.cardiff.nsa.hashenc.engine.ScriptHelper;

@Controller
public class EncryptionController {
	
	/** Class logger. */
    private final Logger log = LoggerFactory.getLogger(EncryptionController.class);
	
	 private static final String TEMPLATE_SCRIPT =
	            "var cipherTextAsBytes = function(message, key){\n"
	            + "   return message.getBytes();\n"
	            + "}\n"
	            + "\n"
	            + "var decodedMessage = function(messageAsBytes, key){\n"
	            + "   var str = '';\n"
	            + "   for (var i=0; i<messageAsBytes.length; ++i) {\n"
	            + "	str+= String.fromCharCode(messageAsBytes[i]);\n"
	            + "    }\n"
	            + "   return str;\n"
	            + "}";
	 
	 /** 
	  * This script state is shared between all users of the application. 
	  * This would need guarding (for thread concurrency) in a real app.
	  * */
	private String script;
	
	public EncryptionController() {
		script = TEMPLATE_SCRIPT;
	}
	
	@GetMapping("/enc") public String getEncryptionPage(final Model model) {
		if (script == null || script.isEmpty()) {
            model.addAttribute("script", TEMPLATE_SCRIPT);
        } else {
            model.addAttribute("script", script);
            model.addAttribute("message", "Text");
            model.addAttribute("key", "10001");
        }
        return "enc";
    }
	
	@PostMapping("/enc-update-script") public String updateScript(
			@RequestParam("script") final String scriptInput,
            final RedirectAttributes model) {
        script = scriptInput;
        model.addFlashAttribute("script", scriptInput);
        return "redirect:enc";
    }
	
	@PostMapping("/encrypt") public String enc(@RequestParam("message") final String message,
			@RequestParam("key") final String key,
            final RedirectAttributes model) {
		
		if (!key.matches("[01]+")) {
			log.error("Key must be binary (a 1 or a 0)");
			//add to result to get it to render
			model.addFlashAttribute("result",  "KEY IS NOT BINARY (only 1 or 0 allowed)");
			model.addFlashAttribute("decryptedMessage",  "KEY IS NOT BINARY (only 1 or 0 allowed)");
			model.addFlashAttribute("message", message);
	        model.addFlashAttribute("key", key);
	        model.addFlashAttribute("script", script);
			return "redirect:enc";
		}
		

        log.info("Message '{}', Script \n{}", message, script);
        model.addFlashAttribute("message", message);
        model.addFlashAttribute("key", key);
        model.addFlashAttribute("script", script);
        
        //assume binary string and parse to long.
        Long keyAsLong = Long.parseLong(key, 2);
        log.info("Key in binary {}",HashEngine.longToBinaryString(keyAsLong));
        log.info("Key in bytes: {}",EncryptionEngine.longToBytesIgnoreZeroBytes(keyAsLong));
        try {
            final Object encResult = ScriptHelper.runEncryptScript("cipherTextAsBytes",script, message, 
                    EncryptionEngine.longToBytesIgnoreZeroBytes(keyAsLong));             
            log.info("Result of encrypt script: {}, {}", encResult, encResult.getClass());
            if (encResult instanceof byte[]) {
            	byte[] encBytes = (byte[]) encResult;
                model.addFlashAttribute("resultHex", EncryptionEngine.byteToHex(encBytes));
                model.addFlashAttribute("resultBinary", EncryptionEngine.byteToBinaryString(encBytes));
                model.addFlashAttribute("result",  EncryptionEngine.byteToHex(message.getBytes()));
                
                final Object decryptResult = ScriptHelper.runEncryptScript("decodedMessage", script, encBytes, key);
               
                log.info("Result of decrypt script: {}, {}", decryptResult, decryptResult.getClass());
                model.addFlashAttribute("decryptedMessage",  decryptResult);

            }
            
            
            
        } catch (NoSuchMethodException | ScriptException e) {
            log.error("Could not run Script", e);
        }

        return "redirect:enc";

    }

}
