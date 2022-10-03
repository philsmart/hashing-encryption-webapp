
package uk.ac.cardiff.nsa.hashenc.context;

import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

/**
 * A context to store state specific to a user
 */
@Component("userContext")
@Scope("session")
public class UserContext {

    /** The current encryption message or plaintext. */
    private String encMessage;

    /** The current encryption key. */
    private String encKey;

    /** The name of the chosen encryption script. */
    private String chosenEncFunction;

    /** The base64 version of the image to show before encryption. */
    private String rawOriginalImageBase64Encoded;

    /** The raw bytes of the encrypted imaged. */
    private String rawEncryptedImageBase64Encoded;

    /** The raw bytes of the decrypted imaged. */
    private String rawDecryptedImageBase64Encoded;

    /**
     * The raw bytes of the uncompressed, unencrypted image, without the header, ready for encryption.
     */
    private byte[] imageBytes;

    public UserContext() {
        encMessage = "Text";
        encKey = "0";
        chosenEncFunction = "caesar-cipher";
    }

    public boolean isImageInitialised() {
        return imageBytes != null;
    }

    public String getEncMessage() {
        return encMessage;
    }

    public void setEncMessage(final String encMessage) {
        this.encMessage = encMessage;
    }

    public String getEncKey() {
        return encKey;
    }

    public void setEncKey(final String encKey) {
        this.encKey = encKey;
    }

    public String getChosenEncFunction() {
        return chosenEncFunction;
    }

    public void setChosenEncFunction(final String chosenEncFunction) {
        this.chosenEncFunction = chosenEncFunction;
    }

    /**
     * Set the rawOriginalImageBase64Encoded.
     *
     * @param rawOriginalImageBase64Encoded the rawOriginalImageBase64Encoded to set
     */
    public final void setRawOriginalImageBase64Encoded(final String rawOriginalImageBase64Encoded) {
        this.rawOriginalImageBase64Encoded = rawOriginalImageBase64Encoded;
    }

    /**
     * Set the rawEncryptedImageBase64Encoded.
     *
     * @param rawEncryptedImageBase64Encoded the rawEncryptedImageBase64Encoded to set
     */
    public final void setRawEncryptedImageBase64Encoded(final String rawEncryptedImageBase64Encoded) {
        this.rawEncryptedImageBase64Encoded = rawEncryptedImageBase64Encoded;
    }

    /**
     * Get the rawDecryptedImageBase64Encoded
     *
     * @return the rawDecryptedImageBase64Encoded
     */
    public final String getRawDecryptedImageBase64Encoded() {
        return rawDecryptedImageBase64Encoded;
    }

    /**
     * Set the rawDecryptedImageBase64Encoded.
     *
     * @param rawDecryptedImageBase64Encoded the rawDecryptedImageBase64Encoded to set
     */
    public final void setRawDecryptedImageBase64Encoded(final String rawDecryptedImageBase64Encoded) {
        this.rawDecryptedImageBase64Encoded = rawDecryptedImageBase64Encoded;
    }

    /**
     * Get a the base64 encoded raw image unencrypted.
     * 
     * @return the original image base64 encoded.
     */
    public String getRawOriginalImageBase64Encoded() {
        return rawOriginalImageBase64Encoded;
    }

    /**
     * Get a the base64 encoded raw image encrypted.
     * 
     * @return the original image base64 encoded.
     */
    public String getRawEncryptedImageBase64Encoded() {
        return rawEncryptedImageBase64Encoded;
    }

    /**
     * Get a live version of the loaded image (body only, no header) bytes.
     * 
     * @return the image body as bytes
     */
    public byte[] getImageBytes() {
        return imageBytes;
    }

    public void setImageBytes(final byte[] imageBytes) {
        this.imageBytes = imageBytes;
    }

}
