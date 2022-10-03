
package uk.ac.cardiff.nsa.hashenc.controller;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

import javax.script.ScriptException;

import org.apache.commons.lang3.RandomStringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import uk.ac.cardiff.nsa.hashenc.context.UserHashingContext;
import uk.ac.cardiff.nsa.hashenc.engine.Dictionary;
import uk.ac.cardiff.nsa.hashenc.engine.HashEngine;
import uk.ac.cardiff.nsa.hashenc.engine.ScriptHelper;
import uk.ac.cardiff.nsa.hashenc.model.BucketsWrapper;

/**
 * Controller that demonstrates simple hashing. Not cryptographic by default, unless a more sophisticated function where
 * constructed.
 */
@Controller
@SessionAttributes("userHashingContext")
public class HashingController {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(HashingController.class);

    private static final String TEMPLATE_SCRIPT = "var hash = function(string){\n" + "    var hash = 0;\n"
            + "    for (var i = 0; i < string.length; i++) {\n" + "      hash = hash + string.charCodeAt(i);\n"
            + "    }\n" + "    return parseInt(hash);\n" + "  \n" + "}";

    /** Dictionary of in-memory words. */
    private final Dictionary wordDictionary;

    /** Constructor. */
    public HashingController() {
        // load the dictionary
        wordDictionary = new Dictionary("dictionary.txt");

    }

    /**
     * Allow spring to create a UserContext and place it inside the HTTP Session for use by the user (JSESSIONID) of
     * this application.
     * 
     * @return the user context.
     */
    @ModelAttribute("userHashingContext")
    public UserHashingContext constructUserContext() {
        final UserHashingContext userContext = new UserHashingContext();
        userContext.setScript(TEMPLATE_SCRIPT);
        return userContext;
    }

    @PostMapping("/update-script")
    public String updateScript(@RequestParam("script") final String scriptInput, final RedirectAttributes model,
            @ModelAttribute("userHashingContext") final UserHashingContext userCtx) {
        userCtx.setScript(scriptInput);
        model.addFlashAttribute("script", scriptInput);
        model.addFlashAttribute("noOfBuckets", "64");
        return "redirect:hashing";
    }

    @GetMapping("/hashing")
    public String getHashingPage(final Model model,
            @ModelAttribute("userHashingContext") final UserHashingContext userCtx) {
        if ((userCtx.getScript() == null) || userCtx.getScript().isEmpty()) {
            model.addAttribute("script", TEMPLATE_SCRIPT);
        } else {
            model.addAttribute("script", (userCtx.getScript()));
        }
        if (!model.containsAttribute("noOfBuckets")) {
            model.addAttribute("noOfBuckets", "64");
        }
        return "hashing";
    }

    @PostMapping("/randomise")
    public String randomise(@RequestParam("no-of-words") final int numberOfWords,
            @RequestParam("no-of-buckets") final int numberOfBuckets, final RedirectAttributes model,
            @ModelAttribute("userHashingContext") final UserHashingContext userCtx) {

        final List<String> randomWords = wordDictionary.getRandomUniqueWords(numberOfWords);
        final BucketsWrapper wrapper = HashEngine.hashToBuckets(randomWords, userCtx.getScript(), numberOfBuckets);
        final int noOfCollisions = HashEngine.numberOfCollisions(wrapper.getBuckets());

        if (numberOfBuckets <= 128) {
            // only add back the number of buckets if there are not that many, otherwise browser death!
            model.addFlashAttribute("buckets", wrapper.getBuckets());
        }
        model.addFlashAttribute("noOfCollisions", noOfCollisions);
        model.addFlashAttribute("hashBits", (Math.log(numberOfBuckets) / Math.log(2)));
        model.addFlashAttribute("noOfBuckets", numberOfBuckets);
        model.addFlashAttribute("no-of-words", numberOfWords);
        model.addFlashAttribute("clusteringMetric", HashEngine.clusterMeasure(wrapper.getBuckets(), numberOfWords));
        model.addFlashAttribute("collisions", wrapper.getExampleCollisions());
        return "redirect:hashing";
    }

    @PostMapping("/hash")
    public String hash(@RequestParam("message") final String message, final RedirectAttributes model,
            @ModelAttribute("userHashingContext") final UserHashingContext userCtx) {

        log.info("Message '{}', Script \n{}", message, userCtx.getScript());
        model.addFlashAttribute("message", message);
        model.addFlashAttribute("script", userCtx.getScript());
        model.addFlashAttribute("messageBinary", HashEngine.stringToBinaryString(message));

        try {
            final Object hashResult = ScriptHelper.runScript(userCtx.getScript(), message);

            if (hashResult instanceof Integer) {
                final int hashInt = (Integer) hashResult;
                model.addFlashAttribute("resultHex", HashEngine.intToHex(hashInt));
                model.addFlashAttribute("resultBinary", HashEngine.intToBinaryString(hashInt));

            }
            if (hashResult instanceof Double) {
                final double hashDbl = (Double) hashResult;
                model.addFlashAttribute("resultHex", HashEngine.doubleToHex(hashDbl));
                model.addFlashAttribute("resultBinary", HashEngine.doubeToBinaryString(hashDbl));

            }

            model.addFlashAttribute("result", hashResult);
            log.info("Result of script: {}, {}", hashResult, hashResult.getClass());
        } catch (NoSuchMethodException | ScriptException e) {
            log.error("Could not run Script", e);
        }

        return "redirect:hashing";

    }

    /**
     * Compute the second preimages using random words.
     */
    @PostMapping("/find-second-preimage-random")
    public String findASecondPreImage(@RequestParam("find-second-preimage") final String message,
            @RequestParam("find-second-preimage-attempts") final int attempts, final RedirectAttributes model,
            @ModelAttribute("userHashingContext") final UserHashingContext userCtx) {
        try {
            final int hashOfGivenInput = (Integer) ScriptHelper.runScript(userCtx.getScript(), message);

            final List<String> secondPreimages = new ArrayList<>();
            for (int i = 0; i < attempts; i++) {
                final int length = ThreadLocalRandom.current().nextInt(0, 20);
                final String randomString = RandomStringUtils.randomAlphabetic(length);
                final Object hashResult = ScriptHelper.runScript(userCtx.getScript(), randomString);
                if (hashResult instanceof Integer) {
                    final int hashInt = (Integer) hashResult;
                    if (hashInt == hashOfGivenInput) {
                        secondPreimages.add(randomString);
                    }
                }
            }
            log.info("Second preimages: {}", secondPreimages);
            model.addFlashAttribute("secondPreimages", secondPreimages);
        } catch (NoSuchMethodException | ScriptException e) {
            log.error("Could not run Script", e);
        }

        return "redirect:hashing";

    }

    /**
     * Compute the preimages using random words. There is no guarantee here the result is an actual preimage it could be
     * a second preimage, so this is just for demonstration. Ideally it could only ever find a single result.
     */
    @PostMapping("/find-preimage-random")
    public String findAPreImage(@RequestParam("find-preimage") final int hash,
            @RequestParam("find-preimage-attempts") final int attempts, final RedirectAttributes model,
            @ModelAttribute("userHashingContext") final UserHashingContext userCtx) {
        try {

            final List<String> preImage = new ArrayList<>();
            for (int i = 0; i < attempts; i++) {
                final int length = ThreadLocalRandom.current().nextInt(0, 20);
                final String randomString = RandomStringUtils.randomAlphabetic(length);
                final Object hashResult = ScriptHelper.runScript(userCtx.getScript(), randomString);
                if (hashResult instanceof Integer) {
                    final int hashInt = (Integer) hashResult;
                    if (hashInt == hash) {
                        preImage.add(randomString);
                    }
                }
            }
            // should only really be a single preimage - so this is just for demo.
            log.info("Preimages: {}", preImage);
            model.addFlashAttribute("preimages", preImage);
        } catch (NoSuchMethodException | ScriptException e) {
            log.error("Could not run Script", e);
        }

        return "redirect:hashing";

    }

    /**
     * Compute the preimage using words in the dictionary. There is no guarantee here the result is an actual preimage
     * it could be a second preimage, so this is just for demonstration. Ideally it could only ever find a single
     * result.
     */
    @PostMapping("/find-preimage-dict")
    public String findAPreImageDictionary(@RequestParam("find-preimage-dict") final int hash,
            @RequestParam("find-preimage-attempts-dict") final int attempts, final RedirectAttributes model,
            @ModelAttribute("userHashingContext") final UserHashingContext userCtx) {
        try {

            final List<String> preimages = new ArrayList<>();
            final List<String> words = wordDictionary.getRandomUniqueWords(attempts);
            for (int i = 0; i < attempts; i++) {
                final Object hashResult = ScriptHelper.runScript(userCtx.getScript(), words.get(i));
                if (hashResult instanceof Integer) {
                    final int hashInt = (Integer) hashResult;
                    if (hashInt == hash) {
                        preimages.add(words.get(i));
                    }
                }
            }
            log.info("Preimages dict: {}", preimages);
            model.addFlashAttribute("preimagesDict", preimages);
        } catch (NoSuchMethodException | ScriptException e) {
            log.error("Could not run Script", e);
        }

        return "redirect:hashing";

    }

    /**
     * Compute the second preimages using words in the dictionary
     */
    @PostMapping("/find-second-preimage-dict")
    public String findASecondPreImageDictionary(@RequestParam("find-second-preimage-dict") final String message,
            @RequestParam("find-second-preimage-attempts-dict") final int attempts, final RedirectAttributes model,
            @ModelAttribute("userHashingContext") final UserHashingContext userCtx) {
        try {
            final int hashOfGivenInput = (Integer) ScriptHelper.runScript(userCtx.getScript(), message);

            final List<String> secondPreimages = new ArrayList<>();
            final List<String> words = wordDictionary.getRandomUniqueWords(attempts);
            for (int i = 0; i < attempts; i++) {
                final Object hashResult = ScriptHelper.runScript(userCtx.getScript(), words.get(i));
                if (hashResult instanceof Integer) {
                    final int hashInt = (Integer) hashResult;
                    if (hashInt == hashOfGivenInput) {
                        secondPreimages.add(words.get(i));
                    }
                }
            }
            log.info("Second preimages dict: {}", secondPreimages);
            model.addFlashAttribute("secondPreimagesDict", secondPreimages);
        } catch (NoSuchMethodException | ScriptException e) {
            log.error("Could not run Script", e);
        }

        return "redirect:hashing";

    }

}
