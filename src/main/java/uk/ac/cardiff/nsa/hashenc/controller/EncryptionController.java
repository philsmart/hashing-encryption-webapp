package uk.ac.cardiff.nsa.hashenc.controller;

import java.util.List;

import javax.script.ScriptException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
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
	 
	 private static final String ONE_TIME_PAD_TEMPLATE = 
		 "var cipherTextAsBytes = function encrypt(message, keyAsBytes){\n" + 
		 "   var bytes = message.getBytes();\n" + 
		 "   if (message.getBytes().length!=keyAsBytes.length){\n" + 
		 "      print(\"Key incompatible\");\n" + 
		 "      return \"\".getBytes();\n" + 
		 "   }\n" + 
		 "   for (var i=0; i<bytes.length; ++i) {\n" + 
		 "        print(\"Before \" + bytes[i]);\n" + 
		 "        var b = bytes[i] ^ keyAsBytes[i];        \n" + 
		 "        bytes[i] = b;\n" + 
		 "        print(\"After: \" + UInt8(bytes[i]));\n" + 
		 "    }    \n" + 
		 "    return bytes;\n" + 
		 "}\n" + 
		 "\n" + 
		 "var decodedMessage = function decrypt(messageAsBytes, keyAsBytes){\n" + 
		 "   if (messageAsBytes.length!=keyAsBytes.length){\n" + 
		 "      print(\"Key incompatible\");\n" + 
		 "      return \"\".getBytes();\n" + 
		 "   }\n" + 
		 "   var str = '';\n" + 
		 "   for (var i=0; i < messageAsBytes.length; ++i) {\n" + 
		 "        // convert signed int in the byte to unsigned before XOR\n" + 
		 "        var decryptedByte = UInt8(messageAsBytes[i]) ^ UInt8(keyAsBytes[i]);\n" + 
		 "        str+= String.fromCharCode(decryptedByte);\n" + 
		 "        \n" + 
		 "    }\n" + 
		 "\n" + 
		 "   return str;\n" + 
		 "}\n" + 
		 "\n" + 
		 "var UInt8 = function (value) {\n" + 
		 "    return (value & 0xFF);\n" + 
		 "};";
	 
	 private static final String BLOCK_CIPHER =
	         "var cipherTextAsBytes = function encrypt(message, keyAsBytes){\n" + 
	         "   var bytes = message.getBytes();\n" + 
	         "   if (message.getBytes().length % keyAsBytes.length != 0){\n" + 
	         "      print(\"Key incompatible\");\n" + 
	         "      return \"\".getBytes();\n" + 
	         "   }\n" + 
	         "   for (var i=0; i<bytes.length; i=i+keyAsBytes.length) {\n" + 
	         "        for (var j = 0; j < keyAsBytes.length; j++){\n" + 
	         "           print(\"Before \" + bytes[i]);\n" + 
	         "           var b = bytes[i+j] ^ keyAsBytes[j];        \n" + 
	         "           bytes[i+j] = b;\n" + 
	         "           print(\"After: \" + UInt8(bytes[i]));\n" + 
	         "        }\n" + 
	         "    }    \n" + 
	         "    return bytes;\n" + 
	         "}\n" + 
	         "\n" + 
	         "var decodedMessage = function decrypt(messageAsBytes, keyAsBytes){\n" + 
	         "   if (messageAsBytes.length % keyAsBytes.length != 0){\n" + 
	         "      print(\"Key incompatible\");\n" + 
	         "      return \"\".getBytes();\n" + 
	         "   }\n" + 
	         "   var str = '';\n" + 
	         "   for (var i=0; i<messageAsBytes.length; i=i+keyAsBytes.length) {\n" + 
	         "        for (var j = 0; j < keyAsBytes.length; j++){\n" + 
	         "           var decryptedByte = messageAsBytes[i+j] ^ keyAsBytes[j];        \n" + 
	         "           str+= String.fromCharCode(decryptedByte);\n" + 
	         "        }\n" + 
	         "    } \n" + 
	         "\n" + 
	         "   return str;\n" + 
	         "}\n" + 
	         "\n" + 
	         "var UInt8 = function (value) {\n" + 
	         "    return (value & 0xFF);\n" + 
	         "};";

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
	private TemplateDTO chosenTemplate;
	
	private List<TemplateDTO> templates = List.of(
	        new TemplateDTO(1, "basic"), new TemplateDTO(2, "One-time-pad"),
	        new TemplateDTO(3,"Block Cipher"));

	public EncryptionController() {		
		message = "Text";
		//4 byte key.
		key = "10111111000010001111111101110010";
		chosenTemplate = templates.get(0);
		script = TEMPLATE_SCRIPT;
	}

	@PostMapping("/set-enc-template") public String updateTemplateScript(
	        @ModelAttribute("templateScript") final TemplateDTO template,
	        final RedirectAttributes model) {
		log.debug("setting template: "+template.getId());
		switch(template.getId()){
			case 1 : script = TEMPLATE_SCRIPT; chosenTemplate = templates.get(0); break;
			case 2 : script = ONE_TIME_PAD_TEMPLATE; chosenTemplate = templates.get(1); break;
			case 3 : script = BLOCK_CIPHER; chosenTemplate = templates.get(2); break;
		}
		
	    return "redirect:enc";
	}

	@GetMapping("/enc")
	public String getEncryptionPage(final Model model) {
		if (script == null || script.isEmpty()) {
			model.addAttribute("script", script);
		} else {
			model.addAttribute("key", key);
			model.addAttribute("message", message);
			model.addAttribute("script", script);
			model.addAttribute("templateScripts", templates);
			model.addAttribute("templateScript", chosenTemplate);
			
		}
		return "enc";
	}

	@PostMapping("/enc-update-script")
	public String updateScript(@RequestParam("script") final String scriptInput, final RedirectAttributes model) {
		script = scriptInput;
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
		log.info("Message in binary {}", HashEngine.stringToBinaryString(message));
		// is wrong if 0 bytes in the middle!
		log.info("Key in bytes: {}", EncryptionEngine.longToBytesIgnoreZeroBytes(keyAsLong));
		log.info("Message in bytes {}",message.getBytes());
		try {
			
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
				model.addFlashAttribute("resultBase64", EncryptionEngine.byteToBase64(encBytes));
				model.addFlashAttribute("resultBinary", EncryptionEngine.byteToBinaryString(encBytes));
				model.addFlashAttribute("result", EncryptionEngine.byteToHex(message.getBytes()));

				final Object decryptResult = ScriptHelper.runEncryptScript("decodedMessage", script, encBytes, 
				        EncryptionEngine.longToBytesIgnoreZeroBytes(keyAsLong));

				log.info("Result of decrypt script: {}, {}", decryptResult, decryptResult.getClass());
				model.addFlashAttribute("decryptedMessage", decryptResult);

			}

		} catch (NoSuchMethodException | ScriptException e) {
			log.error("Could not run Script", e);
		}

		return "redirect:enc";

	}

}

class TemplateDTO{
    
    private final int id;
    
    private final String name;
    
    
    public TemplateDTO(int id, String name) {
        super();
        this.id = id;
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public int getId() {
        return id;
    }


    
}
