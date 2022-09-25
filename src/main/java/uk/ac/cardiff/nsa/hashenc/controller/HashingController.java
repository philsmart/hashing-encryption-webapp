
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
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import uk.ac.cardiff.nsa.hashenc.engine.Dictionary;
import uk.ac.cardiff.nsa.hashenc.engine.HashEngine;
import uk.ac.cardiff.nsa.hashenc.engine.ScriptHelper;
import uk.ac.cardiff.nsa.hashenc.model.BucketsWrapper;

/** 
 * Controller that demonstrates simple hashing. Not cryptographic by default, 
 * unless a more sophisticated function where constructed.
 */
@Controller public class HashingController {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(HashingController.class);

    private static final String TEMPLATE_SCRIPT =
            "var hash = function(string){\n" + 
            "    var hash = 0;\n" + 
            "    for (var i = 0; i < string.length; i++) {\n" + 
            "      hash = hash + string.charCodeAt(i);\n" + 
            "    }\n" + 
            "    return parseInt(hash);\n" + 
            "  \n" + 
            "}";

    /** This script state is shared between all users of the application. */
    private String script;

    /** Dictionary of in-memory words. */
    private Dictionary wordDictionary;

    /** Constructor. */
    public HashingController() {
        script = TEMPLATE_SCRIPT;
        // load the dictionary
        wordDictionary = new Dictionary("dictionary.txt");

    }

    @PostMapping("/update-script") public String updateScript(@RequestParam("script") final String scriptInput,
            final RedirectAttributes model) {
        script = scriptInput;
        model.addFlashAttribute("script", scriptInput);
        model.addFlashAttribute("noOfBuckets", "64");
        return "redirect:hashing";
    }

    @GetMapping("/hashing") public String getHashingPage(final Model model) {
        if (script == null || script.isEmpty()) {
            model.addAttribute("script", TEMPLATE_SCRIPT);
        } else {
            model.addAttribute("script", script);
        }
        if (!model.containsAttribute("noOfBuckets")) {
            model.addAttribute("noOfBuckets", "64");
        }
        return "hashing";
    }
   

    @PostMapping("/randomise") public String randomise(@RequestParam("no-of-words") final int numberOfWords,
            @RequestParam("no-of-buckets") final int numberOfBuckets, final RedirectAttributes model) {

        List<String> randomWords = wordDictionary.getRandomUniqueWords(numberOfWords);
        BucketsWrapper wrapper = HashEngine.hashToBuckets(randomWords, script, numberOfBuckets);
        int noOfCollisions = HashEngine.numberOfCollisions(wrapper.getBuckets());

        //log.debug("Buckets [{}]", wrapper.getBuckets());
        if (numberOfBuckets<=128) {
            //only add back the number of buckets if there are not that many, otherwise browser death!
            model.addFlashAttribute("buckets", wrapper.getBuckets());
        }
        model.addFlashAttribute("noOfCollisions", noOfCollisions);
        model.addFlashAttribute("hashBits", (Math.log(numberOfBuckets)/Math.log(2)));
        model.addFlashAttribute("noOfBuckets", numberOfBuckets);
        model.addFlashAttribute("no-of-words", numberOfWords);
        model.addFlashAttribute("clusteringMetric", HashEngine.clusterMeasure(wrapper.getBuckets(), numberOfWords));
        model.addFlashAttribute("collisions", wrapper.getExampleCollisions());
        return "redirect:hashing";
    }

    @PostMapping("/hash") public String hash(@RequestParam("message") final String message,
            final RedirectAttributes model) {

        log.info("Message '{}', Script \n{}", message, script);
        model.addFlashAttribute("message", message);
        model.addFlashAttribute("script", script);
        model.addFlashAttribute("messageBinary", HashEngine.stringToBinaryString(message));

        try {
            final Object hashResult = ScriptHelper.runScript(script, message);

            if (hashResult instanceof Integer) {
                int hashInt = (Integer) hashResult;
                model.addFlashAttribute("resultHex", HashEngine.intToHex(hashInt));
                model.addFlashAttribute("resultBinary", HashEngine.intToBinaryString(hashInt));

            }
            if (hashResult instanceof Double) {
                double hashDbl = (Double) hashResult;
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
    @PostMapping("/find-second-preimage-random") public String findASecondPreImage(
            @RequestParam("find-second-preimage") final String message,
            @RequestParam("find-second-preimage-attempts") final int attempts, final RedirectAttributes model) {
        try {
            final int hashOfGivenInput = (Integer)ScriptHelper.runScript(script, message);
            
            List<String> secondPreimages = new ArrayList<String>();
            for (int i = 0; i < attempts; i++) {
                int length = ThreadLocalRandom.current().nextInt(0, 20);
                final String randomString = RandomStringUtils.randomAlphabetic(length);
                final Object hashResult = ScriptHelper.runScript(script, randomString);
                if (hashResult instanceof Integer) {
                    int hashInt = (Integer) hashResult;
                    if (hashInt == hashOfGivenInput) {
                        secondPreimages.add(randomString);
                    }
                }
            }
            log.info("Second preimages: {}",secondPreimages);
            model.addFlashAttribute("secondPreimages", secondPreimages);
        } catch (NoSuchMethodException | ScriptException e) {
            log.error("Could not run Script", e);
        }

        return "redirect:hashing";

    }
    
    /**
     * Compute the preimages using random words. There is no guarantee here the result is an actual preimage
     * it could be a second preimage, so this is just for demonstration. Ideally it could only ever find a single result.
     */
    @PostMapping("/find-preimage-random") public String findAPreImage(
            @RequestParam("find-preimage") final int hash,
            @RequestParam("find-preimage-attempts") final int attempts, final RedirectAttributes model) {
        try {      
            
            List<String> preImage = new ArrayList<String>();
            for (int i = 0; i < attempts; i++) {
                int length = ThreadLocalRandom.current().nextInt(0, 20);
                final String randomString = RandomStringUtils.randomAlphabetic(length);
                final Object hashResult = ScriptHelper.runScript(script, randomString);
                if (hashResult instanceof Integer) {
                    int hashInt = (Integer) hashResult;
                    if (hashInt == hash) {
                        preImage.add(randomString);
                    }
                }
            }
            //should only really be a single preimage - so this is just for demo.
            log.info("Preimages: {}",preImage);
            model.addFlashAttribute("preimages", preImage);
        } catch (NoSuchMethodException | ScriptException e) {
            log.error("Could not run Script", e);
        }

        return "redirect:hashing";

    }
    
    /**
     * Compute the preimage using words in the dictionary. There is no guarantee here the result is an actual preimage
     * it could be a second preimage, so this is just for demonstration. Ideally it could only ever find a single result.
     */
    @PostMapping("/find-preimage-dict") public String findAPreImageDictionary(
            @RequestParam("find-preimage-dict") final int hash,
            @RequestParam("find-preimage-attempts-dict") final int attempts, final RedirectAttributes model) {
        try {
            
            List<String> preimages = new ArrayList<String>();
            List<String> words = wordDictionary.getRandomUniqueWords(attempts);
            for (int i = 0; i < attempts; i++) {
                final Object hashResult = ScriptHelper.runScript(script, words.get(i));
                if (hashResult instanceof Integer) {
                    int hashInt = (Integer) hashResult;
                    if (hashInt == hash) {
                        preimages.add(words.get(i));
                    }
                }
            }
            log.info("Preimages dict: {}",preimages);
            model.addFlashAttribute("preimagesDict", preimages);
        } catch (NoSuchMethodException | ScriptException e) {
            log.error("Could not run Script", e);
        }

        return "redirect:hashing";

    }
    
    /**
     * Compute the second preimages using words in the dictionary
     */
    @PostMapping("/find-second-preimage-dict") public String findASecondPreImageDictionary(
            @RequestParam("find-second-preimage-dict") final String message,
            @RequestParam("find-second-preimage-attempts-dict") final int attempts, final RedirectAttributes model) {
        try {
            final int hashOfGivenInput = (Integer)ScriptHelper.runScript(script, message);
            
            List<String> secondPreimages = new ArrayList<String>();
            List<String> words = wordDictionary.getRandomUniqueWords(attempts);
            for (int i = 0; i < attempts; i++) {
                final Object hashResult = ScriptHelper.runScript(script, words.get(i));
                if (hashResult instanceof Integer) {
                    int hashInt = (Integer) hashResult;
                    if (hashInt == hashOfGivenInput) {
                        secondPreimages.add(words.get(i));
                    }
                }
            }
            log.info("Second preimages dict: {}",secondPreimages);
            model.addFlashAttribute("secondPreimagesDict", secondPreimages);
        } catch (NoSuchMethodException | ScriptException e) {
            log.error("Could not run Script", e);
        }

        return "redirect:hashing";

    }

}
