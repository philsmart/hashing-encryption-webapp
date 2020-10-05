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

import uk.ac.cardiff.nsa.hashenc.engine.ScriptHelper;

@Controller
public class HashingController {
    
    /** Class logger.*/
    private final Logger log = LoggerFactory.getLogger(HashingController.class);
    
    private static final String TEMPLATE_SCRIPT = "var hash = function(message){\n" + 
            " return message;\n" + 
            "}";
    
    @GetMapping("/hashing")
    public String getHashingPage(final Model model) {
        if (!model.containsAttribute("script")){
            model.addAttribute("script",TEMPLATE_SCRIPT);
        }
        return "hashing";
    }
    
    @PostMapping("/hash")
    public String hash(@RequestParam("message") final String message, 
            @RequestParam("script") final String script, final RedirectAttributes model) {
              
        log.info("Message '{}', Script \n{}",message,script);
        model.addFlashAttribute("message",message);
        model.addFlashAttribute("script",script);
        
        try {
            final Object hashResult = ScriptHelper.runScript(script, message);
            model.addFlashAttribute("result",hashResult);
            log.info("Result of script: "+hashResult);
        } catch (NoSuchMethodException | ScriptException e) {
           log.error("Could not run Script",e);
        }
        
        return "redirect:hashing";
        
    }

}
