
package uk.ac.cardiff.nsa.hashenc.controller;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import javax.script.ScriptException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import uk.ac.cardiff.nsa.hashenc.engine.EncryptionEngine;
import uk.ac.cardiff.nsa.hashenc.engine.HashEngine;
import uk.ac.cardiff.nsa.hashenc.engine.ImageEngine;
import uk.ac.cardiff.nsa.hashenc.engine.ScriptHelper;

/**
 * Basic Encryption controller. Is not thread-safe and will leak settings between users.
 */
@Controller
public class EncryptionController {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(EncryptionController.class);

    /** A fixed list of encryption script resources. */
    private final Map<String, Resource> encryptionScriptResources =
            Map.of("caesar-cipher", new ClassPathResource("scripts/encryption/caesar-cipher.js"), "one-time-pad",
                    new ClassPathResource("scripts/encryption/one-time-pad.js"), "basic(none)",
                    new ClassPathResource("scripts/encryption/basic.js"), "block-cipher",
                    new ClassPathResource("scripts/encryption/block-cipher.js"), "block-cipher-chaining",
                    new ClassPathResource("scripts/encryption/block-cipher-chaining.js"));

    /** The loaded encryption scripts. Loaded from the encryptionScriptResources on init. */
    private final Map<String, String> encryptionScripts;

    /** The current message. */
    private String message;

    /** The current key. */
    private String key;

    /** The name of the chosen encryption script. */
    private String chosenEncFunction;

    /** Helper for encrypting and decrypting images. */
    @Autowired
    private ImageEngine imageEngine;

    /** Constructor. */
    public EncryptionController() {
        message = "Text";
        // 0 key for default caesar, so no shift, no encryption
        key = "0";
        chosenEncFunction = "caesar-cipher";

        // Load the scripts
        encryptionScripts = new HashMap<>(encryptionScriptResources.size());
        for (final Map.Entry<String, Resource> resource : encryptionScriptResources.entrySet()) {
            final String resourceAsScript = ScriptHelper.loadScriptResourceToString(resource.getValue());
            encryptionScripts.put(resource.getKey(), resourceAsScript);
        }

    }

    /**
     * Set the encryption function (or template script) to use
     * 
     * @param template the encryption function template to choose
     * @param model the model to store the results in
     * 
     * @return a redirect to the 'enc' page.
     */
    @PostMapping("/set-enc-template")
    public String updateTemplateScript(@RequestParam("templateScript") final String template,
            final RedirectAttributes model) {
        log.debug("setting template: " + template);
        chosenEncFunction = template;

        return "redirect:enc";
    }

    /**
     * Get the 'enc' page and set suitable model values.
     * 
     * @param model the model to return
     * 
     * @return the 'enc' page
     */
    @GetMapping("/enc")
    public String getEncryptionPage(final Model model) {
        if ((encryptionScripts.get(chosenEncFunction) == null) || encryptionScripts.get(chosenEncFunction).isEmpty()) {
            log.warn("Script was not choosen");
            model.addAttribute("script", encryptionScripts.get(chosenEncFunction));
        } else {
            model.addAttribute("key", key);
            model.addAttribute("message", message);
            model.addAttribute("imageBase64Unencrypted", imageEngine.getRawOriginalImageBase64Encoded());
            model.addAttribute("imageBase64Encrypted", imageEngine.getRawEncryptedImageBase64Encoded());
            model.addAttribute("imageBase64Decrypted", imageEngine.getRawDecryptedImageBase64Encoded());
            model.addAttribute("script", encryptionScripts.get(chosenEncFunction));
            model.addAttribute("templateScripts",
                    encryptionScripts.entrySet().stream().map(Entry::getKey).collect(Collectors.toList()));
            model.addAttribute("chosenTemplate", chosenEncFunction);

        }
        return "enc";
    }

    /**
     * Update the encryption function (script).
     * 
     * @param scriptInput the new encryption function
     * @param model the model to store the results in
     * 
     * @return a redirect to the 'enc' page
     */
    @PostMapping("/enc-update-script")
    public String updateScript(@RequestParam("script") final String scriptInput, final RedirectAttributes model) {
        encryptionScripts.put(chosenEncFunction, scriptInput);
        return "redirect:enc";
    }

    @GetMapping("/enc-reset-encrypted-image")
    public String resetEncryptedImageAndReload() {
        imageEngine.resetImageToEncryptBytes();
        return "redirect:enc";
    }

    /**
     * Encrypt the message using the key and encryption function provided.
     * 
     * @param message the message to encrypt
     * @param key the key to use
     * @param model the model to store the results in
     * 
     * @return a redirect to the 'enc' page
     */
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
        final String script = encryptionScripts.get(chosenEncFunction);
        log.info("Message '{}', Script \n{}", message, script);
        this.key = key;
        this.message = message;

        // assume binary string and parse to long.
        final Long keyAsLong = Long.parseLong(key, 2);
        log.info("Key in binary {}", HashEngine.longToBinaryString(keyAsLong));
        log.info("Message in binary {}", HashEngine.stringToBinaryString(message));
        // is wrong if 0 bytes in the middle!
        log.info("Key in bytes: {}", EncryptionEngine.longToBytesIgnoreZeroBytes(keyAsLong));
        log.info("Message in bytes {}", message.getBytes());
        try {
            log.info("Encrypting the input text...");
            final Object encResult = ScriptHelper.runEncryptScript("cipherTextAsBytes", script,
                    message.getBytes(StandardCharsets.UTF_8), EncryptionEngine.longToBytesIgnoreZeroBytes(keyAsLong));

            // Now run the image through the script
            log.info("Encrypting the input image...");
            final Object encResultImage = ScriptHelper.runEncryptScript("cipherTextAsBytes", script,
                    imageEngine.getImageBytes(), EncryptionEngine.longToBytesIgnoreZeroBytes(keyAsLong));

            if (encResultImage instanceof byte[]) {
                imageEngine.convertAndReloadEncrypted((byte[]) encResultImage);
            }

            log.info("Result of encrypt script bytes: {}, {}", encResult, encResult.getClass());
            if (encResult instanceof byte[]) {
                final byte[] encBytes = (byte[]) encResult;
                final StringBuilder sb = new StringBuilder();
                for (final byte b : encBytes) {
                    sb.append("[" + HashEngine.byteToBinary(b) + "]");
                }
                log.info("Returned message as binary: {}", sb.toString());
                model.addFlashAttribute("resultHex", EncryptionEngine.byteToHex(encBytes));
                model.addFlashAttribute("resultBase64", EncryptionEngine.byteToBase64(encBytes));
                model.addFlashAttribute("resultUTF8String", EncryptionEngine.attemptUTF8String(encBytes));
                model.addFlashAttribute("resultBinary", EncryptionEngine.byteToBinaryString(encBytes));
                model.addFlashAttribute("result", EncryptionEngine.byteToHex(message.getBytes()));
                model.addFlashAttribute("imageBase64Encrypted", imageEngine.getRawEncryptedImageBase64Encoded());

                log.info("Decrypting the input text...");
                final Object decryptResult = ScriptHelper.runEncryptScript("decodedMessageAsBytes", script, encBytes,
                        EncryptionEngine.longToBytesIgnoreZeroBytes(keyAsLong));

                if (decryptResult instanceof byte[]) {
                    log.info("Result of decrypt script: {}, {}", decryptResult, decryptResult.getClass());
                    model.addFlashAttribute("decryptedMessage",
                            new String((byte[]) decryptResult, StandardCharsets.UTF_8));
                }

                log.info("Decrypting the input image...");
                final Object decResultImage = ScriptHelper.runEncryptScript("decodedMessageAsBytes", script,
                        imageEngine.getImageBytes(), EncryptionEngine.longToBytesIgnoreZeroBytes(keyAsLong));
                if (decResultImage instanceof byte[]) {
                    imageEngine.convertAndReloadDecrypted((byte[]) decResultImage);
                }

            }

        } catch (NoSuchMethodException | ScriptException e) {
            log.error("Could not run Script", e);
        }

        return "redirect:enc";

    }

}
