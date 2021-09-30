
package uk.ac.cardiff.nsa.hashenc.engine;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

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
        //will always produce 8 bytes as that is the max size of a long 64 bit.
        List<Byte> byteList = new ArrayList<>(bytes.length);
        for (byte b : bytes) {
            if (b != 0) {
                byteList.add(b);
            }
        }
        return ArrayUtils.toPrimitive(byteList.toArray(new Byte[0]));
    }

}
