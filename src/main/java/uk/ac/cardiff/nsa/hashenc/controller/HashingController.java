
package uk.ac.cardiff.nsa.hashenc.controller;

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

import uk.ac.cardiff.nsa.hashenc.engine.ScriptHelper;

@Controller public class HashingController {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(HashingController.class);

    private static final String TEMPLATE_SCRIPT = "var hash = function(string){\n" + "    var H = 37;\n"
            + "    var total = 0;\n" + "\n" + "    for (var i = 0; i < string.length; i++) {\n"
            + "      total += H * total + string.charCodeAt(i);\n" + "    }\n" + "    total = total % 32;\n"
            + "    return parseInt(total);\n" + "  \n" + "}";

    /** This script state is shared between all users of the application. */
    private String script;
    
    /** Constructor.*/
    public HashingController() {
        script = TEMPLATE_SCRIPT;               
    }

    @PostMapping("/update-script") 
    public String updateScript(@RequestParam("script") final String scriptInput,
            final RedirectAttributes model) {
        script = scriptInput;
        model.addFlashAttribute("script", scriptInput);
        return "redirect:hashing";
    }

    @GetMapping("/hashing") 
    public String getHashingPage(final Model model) {   
        if (script == null || script.isEmpty()) {
            model.addAttribute("script", TEMPLATE_SCRIPT);
        } else {
            model.addAttribute("script", script);
        }
        return "hashing";
    }

    @PostMapping("/randomise") 
    public String randomise(@RequestParam("no-of-words") final int numberOfWords) {
        try {
            for (int i = 0; i < numberOfWords; i++) {
                final String generatedString = RandomStringUtils.randomAlphanumeric(5);
                final Object hashResult = ScriptHelper.runScript(script, generatedString);
                log.debug("Hashed '{}' = '{}'", generatedString, hashResult);
            }
        } catch (NoSuchMethodException | ScriptException e) {
            log.error("Could not run Script", e);
        }
        return "redirect:hashing";
    }

    @PostMapping("/hash")
    public String hash(@RequestParam("message") final String message, 
            final RedirectAttributes model) {
              
        log.info("Message '{}', Script \n{}",message,script);
        model.addFlashAttribute("message",message);
        model.addFlashAttribute("script",script);
        
        try {
            final Object hashResult = ScriptHelper.runScript(script, message);
            model.addFlashAttribute("result",hashResult);
            log.info("Result of script: "+hashResult);
        } catch (NoSuchMethodException | ScriptException e) {
            log.error("Could not run Script", e);
        }
        
        return "redirect:hashing";
        
    }

}
