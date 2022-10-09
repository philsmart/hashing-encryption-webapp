package uk.ac.cardiff.nsa.hashenc.engine;

import java.nio.charset.StandardCharsets;

import org.apache.commons.codec.binary.Base64;

/**
 * Some util methods to help construct very simple JWTs - use Nimbus
 * or better libraries in production system.
 */
public final class JWTUtils {
	
	public final static String DEFAULT_JOSE_HEADER = """
			{
				"alg": "HS256",
				"typ": "JWT"
			}
			""";
	
	private JWTUtils() {
		
	}
	
	/**
	 * Construct a JWT/JWS/JWE using the compact serialization scheme.
	 * 
	 * @param header the header, can be null, if so the default JOSE header will be used.
	 * @param payload the payload
	 * @return the compact serialization
	 */
	public static String createJWTCompactSerlizationForSigning(String header, String payload) {
		String headerB64 = header == null ? Base64.encodeBase64URLSafeString(normalise(DEFAULT_JOSE_HEADER).getBytes(StandardCharsets.UTF_8)) : 
			Base64.encodeBase64URLSafeString(normalise(header).getBytes(StandardCharsets.UTF_8));
		String payloadB64 =  Base64.encodeBase64URLSafeString(normalise(payload).getBytes(StandardCharsets.UTF_8));
		
		return headerB64+"."+payloadB64;
	}
	
	public static String normalise(String in) {
		return in.replaceAll("\\s+", "");
	}

	public static Object appendSignature(String compactHeaderPayload, byte[] mac) {
		return compactHeaderPayload+"."+Base64.encodeBase64URLSafeString(mac);
	}

}
