
package uk.ac.cardiff.nsa.hashenc.engine;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.script.ScriptException;

import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import uk.ac.cardiff.nsa.hashenc.model.BucketsWrapper;

/** Helper methods for dealing with hashing functions. */
public class HashEngine {

    /** Class logger. */
    private static final Logger log = LoggerFactory.getLogger(HashEngine.class);

    public static BucketsWrapper hashToBuckets(final List<String> messages, final String script, final int noBuckets) {

        //last bucket is the overflow bucket.
        int[] buckets = new int[noBuckets+1];
        //cheat here to find collisions as examples by using an actual hashmap
        HashMap<Integer,String> collisions = new HashMap<Integer,String>();
        List<String[]> exampleCollisions = new ArrayList<String[]>();
        for (final String message : messages) {
            try {
                Object hashResult = ScriptHelper.runScript(script, message);
                log.debug("Input({}) = Hash({}), {}", message, hashResult,hashResult.getClass());
                
                if (hashResult instanceof Integer) {
                    int hashInt = (Integer)hashResult;

                    if (hashInt >=0 && hashInt < noBuckets) {                       
                        buckets[hashInt]++;
                        if (collisions.containsKey(hashInt)) {
                            String[] example = new String[] {collisions.get(hashInt),message};
                            exampleCollisions.add(example);
                        } else {
                            collisions.put(hashInt, message);
                        }
                    } else {
                        log.debug("Hash it outside output range! {}",hashInt);
                        buckets[buckets.length-1]++;
                        if (collisions.containsKey(buckets.length-1)) {
                            String[] example = new String[] {collisions.get(buckets.length-1),message};
                            exampleCollisions.add(example);
                        } else {
                            collisions.put(buckets.length-1, message);
                        }
                    }
                    
                }
                //likely too big by this point. Lots of lossy conversion here.
                if (hashResult instanceof Double) {
                    Double hashDbl = (Double) hashResult;
                    //log.debug("HashInt {}",hashInt);
                    if (hashDbl.intValue() >=0 && hashDbl.intValue() < noBuckets) {                       
                        buckets[hashDbl.intValue()]++;
                    } else {
                        log.debug("Hash it outside output range! {}",hashDbl);
                        buckets[buckets.length-1]++;
                    }
                    
                }
                
            } catch (final NoSuchMethodException | ScriptException e) {
                //mostly suppress the error
                log.error("Could not generate hash for message '{}'", message, e.getMessage());
            }
        } 
        
        return new BucketsWrapper(buckets, exampleCollisions);

    }
    
    public static int numberOfCollisions(final int[] buckets) {
        int totalCollisions = 0;
        for (int i = 0; i < buckets.length; i++) {
            if (buckets[i]>1) {
                //record collision, ignore first in bucket
                totalCollisions+=buckets[i]-1;
            }
        }
        return totalCollisions;
    }
    
    public static String intToHex(final int diffusedHash) {
        return Integer.toHexString(diffusedHash);
    }
    
    public static String doubleToHex(final double diffusedHash) {
        return Double.toHexString(diffusedHash);
    }
    
    public static String stringToBinaryString(final String message) {
        StringBuilder builder = new StringBuilder();
        for (final byte b : message.getBytes()) {
            builder.append("[").append(byteToBinary(b)).append("]");
        }
        return builder.toString();
    }
    
    public static String intToBinaryString(final int diffusedHash) {
     
        StringBuilder builder = new StringBuilder();
        for (final byte b : toByteArray(diffusedHash)) {
            builder.append("[").append(byteToBinary(b)).append("]");
        }
        return builder.toString();
    }
    
    public static String doubeToBinaryString(final double diffusedHash) {
        byte [] bytes = ByteBuffer.allocate(8).putDouble(diffusedHash).array();
        StringBuilder builder = new StringBuilder();
        for (final byte b : bytes) {
            builder.append("[").append(byteToBinary(b)).append("]");
        }
        return builder.toString();
    }
    
    /**
     * Generate a sha256 non-cryptographic hash for a string.
     * 
     * @param message the message to hash, never {@literal null}.
     * @return a Hexadecimal representation of the hash.
     */
    public static String constructCryptographicHash(final String message) {
        Objects.requireNonNull(message, "Input message can not be null");

        try {
            final MessageDigest digest = MessageDigest.getInstance("SHA-256");
            final byte[] encodedhash = digest.digest(message.getBytes(StandardCharsets.UTF_8));
            return Hex.encodeHexString(encodedhash);

        } catch (final NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }

    }
    
    /**
     * Return a bit string representation of the byte argument.
     * 
     * @param b the byte to convert to a bit string.
     * @return the bit string representation.
     */
    public static String byteToBinary(final byte b) {

        return String.format("%8s", Integer.toBinaryString((b + 256) % 256)).replace(' ', '0');

    }
    
    public static double clusterMeasure(final int[] buckets, int elementsInHash) {
        double m = buckets.length;
        double n = elementsInHash;

        double elementTotal = 0;
        for (int element : buckets) {
            elementTotal += element * (element+1);
        }
        elementTotal = elementTotal -1;
        return (elementTotal * m / (n * (n + 2 * m -1)));
    }
    
    public static byte[] toByteArray(int value) {
        return new byte[] {
                (byte)(value >> 24),
                (byte)(value >> 16),
                (byte)(value >> 8),
                (byte)value};
    }

    /**
     * Construct a HMAC based on the SHA256 hashing algorithm.
     * 
     * @param docOne the document to generate a HMAC for
     * @param key the key to use with the hash to generate the HMAC
     * @return the HMAC represented as HEX.
     */
    public static String constructHmac(final String docOne, final String key) {
        try {
            final byte[] byteKey = key.getBytes(StandardCharsets.UTF_8);
            Mac sha512Hmac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(byteKey, ("HmacSHA256"));
            sha512Hmac.init(keySpec);
            byte[] macData = sha512Hmac.doFinal(docOne.getBytes(StandardCharsets.UTF_8));
            return new String(Hex.encodeHex(macData));
        } catch (final NoSuchAlgorithmException | InvalidKeyException e) {
            return null;
        } 
    }

}
