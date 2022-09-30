
package uk.ac.cardiff.nsa.hashenc.engine;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.ArrayUtils;

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

	public static byte[] longToBytesIgnoreZeroBytes(final long diffusedHash) {
		ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
		buffer.putLong(diffusedHash);
		byte[] bytes = buffer.array();
		// will always produce 8 bytes as that is the max size of a long 64 bit.
		List<Byte> byteList = new ArrayList<>(bytes.length);
		for (byte b : bytes) {
			if (b != 0) {
				byteList.add(b);
			}
		}
		return ArrayUtils.toPrimitive(byteList.toArray(new Byte[0]));
	}

	public static String byteToBase64(byte[] encBytes) {
		return Base64.encodeBase64String(encBytes);
	}

	/**
	 * Convert the bytes to UTF-8 w that makes sense or not.
	 * 
	 * @param encBytes the bytes to convert to a string
	 * @return the converted bytes as a string
	 */
	public static Object attemptUTF8String(byte[] encBytes) {
		return new String(encBytes, StandardCharsets.UTF_8);
	}

}
