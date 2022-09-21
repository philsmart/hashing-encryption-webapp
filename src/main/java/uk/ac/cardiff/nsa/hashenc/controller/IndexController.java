package uk.ac.cardiff.nsa.hashenc.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Index or home page controller
 */
@Controller
public class IndexController {
    
    /**
     * Index is actually the hashing page.
     * 
     * @return
     */
    @GetMapping("/")
    public String getIndexPage() {
        return "redirect:/hashing";
    }

}
