package uk.ac.cardiff.nsa.hashenc.engine;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Scanner;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** 
 * Dictionary instance which holds 
 */
public class Dictionary {
    
    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(Dictionary.class);
    
    /** List of words loaded from the dictionary file.*/
    final List<String> words;
    
    /**
     * Constructor. Loads the dictionary file.
     * 
     * @param dictionaryFile the list of words to load.
     */
    public Dictionary(final String dictionaryFile) {
        InputStream is = getClass().getClassLoader().getResourceAsStream(dictionaryFile);
        Scanner scanner = new Scanner(is);
        words = new ArrayList<>();
        while (scanner.hasNextLine()) {
            words.add(scanner.nextLine().trim());
        }
        scanner.close();
        log.info("Loaded {} words into the dictonary",words.size());
    }
    
    public List<String> getRandomUniqueWords(final int count) {
        
        //keep adding words until we have the required amount of unique words
        Set<String> uniqueWords = new HashSet<String>();
        while (uniqueWords.size() < count) {
            int indx = ThreadLocalRandom.current().nextInt(0, words.size());
            uniqueWords.add(words.get(indx));
        }
        return new ArrayList<String>(uniqueWords);
        
    }

}
