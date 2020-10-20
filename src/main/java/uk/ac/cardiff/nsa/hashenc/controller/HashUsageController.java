
package uk.ac.cardiff.nsa.hashenc.controller;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

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

@Controller public class HashUsageController {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(HashUsageController.class);

    /** Dictionary of in-memory words. */
    private Dictionary wordDictionary;

    /** Constructor. */
    public HashUsageController() {
        wordDictionary = new Dictionary("dictionary.txt");

    }

    @GetMapping("/hashing-usage") public String getHashingUsagePage(final Model model) {
        return "hashing-usage";
    }

    @PostMapping("/hash-password") public String hashPassword(@RequestParam("password") final String password,
            final RedirectAttributes model) {

        final String hexHashedPassword = HashEngine.constructCryptographicHash(password);
        model.addFlashAttribute("hashed", hexHashedPassword);
        model.addFlashAttribute("hashedInt", new BigInteger(hexHashedPassword, 16).toString());
        return "redirect:hashing-usage";
    }
    
    @PostMapping("/hash-documents") public String hashDocuments(@RequestParam("docTwo") final String docTwo,
            final RedirectAttributes model) {

        final String docTwoHash = HashEngine.constructCryptographicHash(docTwo);
        model.addFlashAttribute("docTwoHash", docTwoHash);
        model.addFlashAttribute("docTwo", docTwo);
        model.addFlashAttribute("match", docTwoHash.equals("40d2c42d9c170b0699fd898acecf01df0ccd8efc70b294be17816956b265b968"));
        return "redirect:hashing-usage";
    }
    
    @PostMapping("/hmac-document") public String hmacDocuments(@RequestParam("docOne") final String docOne,
            @RequestParam("key") final String key,
            final RedirectAttributes model) {

        final String docOneHmac = HashEngine.constructHmac(docOne,key);
        final String docOneHash = HashEngine.constructCryptographicHash(docOne);
       
        model.addFlashAttribute("docOneHash", docOneHash);
        model.addFlashAttribute("docOneHmac", docOneHmac);
        return "redirect:hashing-usage";
    }

    @PostMapping("/crack-password") public String crackPassword(@RequestParam("hex-hash") final String hexHash,
            @RequestParam("attempts") final int attempts, final RedirectAttributes model) {

        List<String> preimages = new ArrayList<String>();
        List<String> words = wordDictionary.getRandomUniqueWords(attempts);
        log.debug("Generated {} words",words.size());
        for (int i = 0; i < attempts; i++) {
            String wordHash = HashEngine.constructCryptographicHash(words.get(i));
          
            if (wordHash.equals(hexHash)) {
                preimages.add(words.get(i));
            }
        }
        log.info("Pre-images dict: {}", preimages);
        model.addFlashAttribute("preimagesDict", preimages);

        return "redirect:hashing-usage";
    }

}
