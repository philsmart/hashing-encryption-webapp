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
	            "var cipherTextAsBytes = function encrypt(message, keyAsBytes){\n"
	            + "   return message.getBytes();\n"
	            + "}\n"
	            + "\n"
	            + "var decodedMessage = function decrypt(messageAsBytes, key){\n"
	            + "   var str = '';\n"
	            + "   for (var i=0; i<messageAsBytes.length; ++i) {\n"
	            + "	str+= String.fromCharCode(messageAsBytes[i]);\n"
	            + "    }\n"
	            + "   return str;\n"
	            + "}";
	 
	 private static final String BASIC_XOR_TEMPLATE = 
		 "var cipherTextAsBytes = function encrypt(message, keyAsBytes){\n"
		 + "   var bytes = message.getBytes();\n"
		 + "   var bytesOut = [];\n"
		 + "   for (var i=0; i<bytes.length; ++i) {\n"
		 + "        print(\"Before \" + bytes[i]);\n"
		 + "        var b = bytes[i] ^ 0xFF;        \n"
		 + "        bytes[i] = b;\n"
		 + "        print(\"After: \" + UInt8(bytes[i]));\n"
		 + "    }    \n"
		 + "    return bytes;\n"
		 + "}\n"
		 + "\n"
		 + "var decodedMessage = function decrypt(messageAsBytes, key){\n"
		 + "   var str = '';\n"
		 + "   print(\"Type of message: \"+typeof messageAsBytes);\n"
		 + "   for (var i=0; i < messageAsBytes.length; ++i) {\n"
		 + "        // convert signed int in the byte to unsigned before XOR\n"
		 + "        var decryptedByte = UInt8(messageAsBytes[i]) ^ 0xFF;\n"
		 + "	str+= String.fromCharCode(decryptedByte);\n"
		 + "        \n"
		 + "    }\n"
		 + "\n"
		 + "   return str;\n"
		 + "}\n"
		 + "\n"
		 + "var UInt8 = function (value) {\n"
		 + "	return (value & 0xFF);\n"
		 + "};";

	/**
	 * This script state is shared between all users of the application. This would
	 * need guarding (for thread concurrency) in a real app.
	 */
	private String script;
	
	/** The current message.*/
	private String message;
	
	/** The current key.*/
	private String key;
	
	/** The name of the choosen script.*/
	private String chosenScript;

	public EncryptionController() {
		script = TEMPLATE_SCRIPT;
		message = "Text";
		key = "10101100";
		chosenScript = "tempOne";
	}

	@PostMapping("/set-enc-template") public String updateTemplateScript(
			@RequestParam("chosenScript") final String scriptName,
	        final RedirectAttributes model) {
		log.debug("setting script: "+scriptName);
		switch(scriptName){
			case "tempOne" : script = TEMPLATE_SCRIPT; chosenScript = "tempOne"; break;
			case "basicXOR" : script = BASIC_XOR_TEMPLATE; chosenScript = "basicXOR"; break;
		}
		
	    model.addFlashAttribute("script", script);
	    return "redirect:enc";
	}

	@GetMapping("/enc")
	public String getEncryptionPage(final Model model) {
		if (script == null || script.isEmpty()) {
			model.addAttribute("script", TEMPLATE_SCRIPT);
		} else {
			model.addAttribute("key", key);
			model.addAttribute("message", message);
			model.addAttribute("script", script);
			model.addAttribute("chosenScript", chosenScript);
			
		}
		return "enc";
	}

	@PostMapping("/enc-update-script")
	public String updateScript(@RequestParam("script") final String scriptInput, final RedirectAttributes model) {
		script = scriptInput;
		model.addFlashAttribute("script", scriptInput);
		return "redirect:enc";
	}

	@PostMapping("/encrypt")
	public String enc(@RequestParam("message") final String message, @RequestParam("key") final String key,
			final RedirectAttributes model) {

		if (!key.matches("[01]+")) {
			log.error("Key must be binary (a 1 or a 0)");
			// add to result to get it to render
			model.addFlashAttribute("result", "KEY IS NOT BINARY (only 1 or 0 allowed)");
			model.addFlashAttribute("decryptedMessage", "KEY IS NOT BINARY (only 1 or 0 allowed)");
			return "redirect:enc";
		}

		log.info("Message '{}', Script \n{}", message, script);
		this.key = key;
		this.message = message;

		// assume binary string and parse to long.
		Long keyAsLong = Long.parseLong(key, 2);
		log.info("Key in binary {}", HashEngine.longToBinaryString(keyAsLong));
		log.info("Key in bytes: {}", EncryptionEngine.longToBytesIgnoreZeroBytes(keyAsLong));
		try {
			log.info("Message in bytes {}",message.getBytes());
			final Object encResult = ScriptHelper.runEncryptScript("cipherTextAsBytes", script, message,
					EncryptionEngine.longToBytesIgnoreZeroBytes(keyAsLong));
			
			
			log.info("Result of encrypt script bytes: {}, {}", encResult, encResult.getClass());
			if (encResult instanceof byte[]) {
				byte[] encBytes = (byte[]) encResult;
				StringBuilder sb = new StringBuilder();
				for (byte b : encBytes) {
					sb.append("["+HashEngine.byteToBinary(b)+"]");
				}
				log.info("Returned message as binary: {}",sb.toString());
				model.addFlashAttribute("resultHex", EncryptionEngine.byteToHex(encBytes));
				model.addFlashAttribute("resultBinary", EncryptionEngine.byteToBinaryString(encBytes));
				model.addFlashAttribute("result", EncryptionEngine.byteToHex(message.getBytes()));

				final Object decryptResult = ScriptHelper.runEncryptScript("decodedMessage", script, encBytes, key);

				log.info("Result of decrypt script: {}, {}", decryptResult, decryptResult.getClass());
				model.addFlashAttribute("decryptedMessage", decryptResult);

			}

		} catch (NoSuchMethodException | ScriptException e) {
			log.error("Could not run Script", e);
		}

		return "redirect:enc";

	}

}
