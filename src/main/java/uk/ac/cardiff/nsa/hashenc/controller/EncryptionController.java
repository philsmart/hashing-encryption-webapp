
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
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import uk.ac.cardiff.nsa.hashenc.context.UserContext;
import uk.ac.cardiff.nsa.hashenc.engine.EncryptionEngine;
import uk.ac.cardiff.nsa.hashenc.engine.HashEngine;
import uk.ac.cardiff.nsa.hashenc.engine.ImageEngine;
import uk.ac.cardiff.nsa.hashenc.engine.ScriptHelper;

/**
 * Basic Encryption controller. Is not thread-safe and will leak settings between users.
 * 
 * <p>
 * Note, 'message' is used here in place of 'plaintext'.
 * </p>
 */
@Controller
@SessionAttributes("userContext")
public class EncryptionController {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(EncryptionController.class);

    /** A fixed list of encryption script resources. */
    private final Map<String, Resource> encryptionScriptResources = Map.of("caesar-cipher",
            new ClassPathResource("scripts/encryption/caesar-cipher.js"), "one-time-pad",
            new ClassPathResource("scripts/encryption/one-time-pad.js"), "basic(none)",
            new ClassPathResource("scripts/encryption/basic.js"), "block-cipher",
            new ClassPathResource("scripts/encryption/block-cipher.js"), "block-cipher-chaining (Experimental)",
            new ClassPathResource("scripts/encryption/block-cipher-chaining.js"), "block-cipher-counter (Experimental)",
            new ClassPathResource("scripts/encryption/block-cipher-counter.js"));

    /**
     * The loaded encryption scripts. Loaded from the encryptionScriptResources on init.
     */
    private final Map<String, String> encryptionScripts;

    /** Engine for dealing with images. */
    @Autowired
    private ImageEngine imageEngine;

    /** Constructor. */
    public EncryptionController() {

        // Load the scripts
        encryptionScripts = new HashMap<>(encryptionScriptResources.size());
        for (final Map.Entry<String, Resource> resource : encryptionScriptResources.entrySet()) {
            final String resourceAsScript = ScriptHelper.loadScriptResourceToString(resource.getValue());
            encryptionScripts.put(resource.getKey(), resourceAsScript);
        }
    }

    /**
     * Allow spring to create a UserContext and place it inside the HTTP Session for use by the user (JSESSIONID) of
     * this application.
     * 
     * @return the user context.
     */
    @ModelAttribute("userContext")
    public UserContext constructUserContext() {
        final UserContext userContext = new UserContext();
        imageEngine.loadUserContext(userContext);
        return userContext;
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
            final RedirectAttributes model, @ModelAttribute("userContext") final UserContext userCtx) {
        log.debug("setting template: " + template);
        userCtx.setChosenEncFunction(template);
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
    public String getEncryptionPage(final Model model, @ModelAttribute("userContext") final UserContext userCtx) {
        if ((encryptionScripts.get(userCtx.getChosenEncFunction()) == null)
                || encryptionScripts.get(userCtx.getChosenEncFunction()).isEmpty()) {
            log.warn("Script was not choosen");
            model.addAttribute("script", encryptionScripts.get(userCtx.getChosenEncFunction()));
        } else {
            model.addAttribute("key", userCtx.getEncKey());
            model.addAttribute("message", userCtx.getEncMessage());
            model.addAttribute("imageBase64Unencrypted", userCtx.getRawOriginalImageBase64Encoded());
            model.addAttribute("imageBase64Encrypted", userCtx.getRawEncryptedImageBase64Encoded());
            model.addAttribute("imageBase64Decrypted", userCtx.getRawDecryptedImageBase64Encoded());
            model.addAttribute("script", encryptionScripts.get(userCtx.getChosenEncFunction()));
            model.addAttribute("templateScripts",
                    encryptionScripts.entrySet().stream().map(Entry::getKey).collect(Collectors.toList()));
            model.addAttribute("chosenTemplate", userCtx.getChosenEncFunction());

        }
        return "enc";
    }

    /**
     * Update the encryption function (script).
     * 
     * @param scriptInput the new encryption function
     * @param model the model to store the results in
     * @param userCtx the user context from the HTTP Session
     * 
     * @return a redirect to the 'enc' page
     */
    @PostMapping("/enc-update-script")
    public String updateScript(@RequestParam("script") final String scriptInput, final RedirectAttributes model,
            @ModelAttribute("userContext") final UserContext userCtx) {
        encryptionScripts.put(userCtx.getChosenEncFunction(), scriptInput);
        return "redirect:enc";
    }

    @GetMapping("/enc-reset-encrypted-image")
    public String resetEncryptedImageAndReload(@ModelAttribute("userContext") final UserContext userCtx) {
        imageEngine.resetImageEncryption(userCtx);
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
            final RedirectAttributes model, @ModelAttribute("userContext") final UserContext userCtx) {

        if (!key.matches("[01]+")) {
            log.error("Key must be binary (a 1 or a 0)");
            // add to result to get it to render
            model.addFlashAttribute("result", "KEY IS NOT BINARY (only 1 or 0 allowed)");
            model.addFlashAttribute("decryptedMessage", "KEY IS NOT BINARY (only 1 or 0 allowed)");
            return "redirect:enc";
        }
        final String script = encryptionScripts.get(userCtx.getChosenEncFunction());
        log.info("Message '{}', Script \n{}", message, script);
        userCtx.setEncKey(key);
        userCtx.setEncMessage(message);

        // assume binary string and parse to long.
        final Long keyAsLong = Long.parseLong(key, 2);
        logKeyAndMessageInfo(keyAsLong, message);
        try {
            log.info("Encrypting the input text...");
            final Object encResult = ScriptHelper.runEncryptScript("cipherTextAsBytes", script,
                    message.getBytes(StandardCharsets.UTF_8), EncryptionEngine.longToBytesIgnoreZeroBytes(keyAsLong));

            // Now run the image through the script
            log.info("Encrypting the input image...");
            final Object encResultImage = ScriptHelper.runEncryptScript("cipherTextAsBytes", script,
                    userCtx.getImageBytes(), EncryptionEngine.longToBytesIgnoreZeroBytes(keyAsLong));

            if (encResultImage instanceof byte[]) {
                imageEngine.convertAndReloadEncrypted((byte[]) encResultImage, userCtx);
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
                model.addFlashAttribute("imageBase64Encrypted", userCtx.getRawEncryptedImageBase64Encoded());

                log.info("Decrypting the input text...");
                final Object decryptResult = ScriptHelper.runEncryptScript("decodedMessageAsBytes", script, encBytes,
                        EncryptionEngine.longToBytesIgnoreZeroBytes(keyAsLong),
                        new byte[userCtx.getImageBytes().length]);

                if (decryptResult instanceof byte[]) {
                    model.addFlashAttribute("decryptedMessage",
                            new String((byte[]) decryptResult, StandardCharsets.UTF_8));
                }

                log.info("Decrypting the input image...");
                final Object decResultImage = ScriptHelper.runEncryptScript("decodedMessageAsBytes", script,
                        userCtx.getImageBytes(), EncryptionEngine.longToBytesIgnoreZeroBytes(keyAsLong),
                        new byte[userCtx.getImageBytes().length]);

                if (decResultImage instanceof byte[]) {
                    imageEngine.convertAndReloadDecrypted((byte[]) decResultImage, userCtx);
                }

            }

        } catch (NoSuchMethodException | ScriptException e) {
            log.error("Could not run Script", e);
        }

        return "redirect:enc";

    }

    private void logKeyAndMessageInfo(final Long keyAsLong, final String message) {
        if (log.isInfoEnabled()) {
            log.info("Key in binary {}", HashEngine.longToBinaryString(keyAsLong));
            log.info("Message in binary {}", HashEngine.stringToBinaryString(message));
            // is wrong if 0 bytes in the middle!
            log.info("Key in bytes: {}", EncryptionEngine.longToBytesIgnoreZeroBytes(keyAsLong));
            log.info("Message in bytes {}", message.getBytes());
        }
    }

}
