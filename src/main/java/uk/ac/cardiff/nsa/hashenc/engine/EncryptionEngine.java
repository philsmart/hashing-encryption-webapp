package uk.ac.cardiff.nsa.hashenc.engine;

import org.apache.commons.codec.binary.Hex;

public class EncryptionEngine {
	
	public static String byteToBinaryString(final byte[] bytes) {
        StringBuilder builder = new StringBuilder();
        for (final byte b : bytes) {
            builder.append("[").append(HashEngine.byteToBinary(b)).append("]");
        }
        return builder.toString();
    }
	
	 public static String byteToHex(final byte[] bytes) {
	        return Hex.encodeHexString(bytes);
	    }

}
