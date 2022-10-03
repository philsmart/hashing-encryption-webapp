
package uk.ac.cardiff.nsa.hashenc.engine;

import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import javax.imageio.ImageIO;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import com.twelvemonkeys.imageio.stream.ByteArrayImageInputStream;

import uk.ac.cardiff.nsa.hashenc.context.UserContext;
import uk.ac.cardiff.nsa.hashenc.controller.EncryptionController;

/**
 * Only supports the image given.
 */
@Component
public class ImageEngine {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(EncryptionController.class);

    /** The specific header of the 'tux' ppm image. */
    private final String PPM_HEADER = "P6\n" + "196 216\n" + "255\n";

    /**
     * A sample image to try encrypting. The header should be removed from the file.
     */
    private final Resource imageToEncrypt = new ClassPathResource("tux-no-header.ppm");

    /** The original image to show before encryption. */
    private final Resource originalImage = new ClassPathResource("tux.jpg");

    public ImageEngine() {
        log.info("ImageIO suports '{}'", Arrays.asList(ImageIO.getReaderFormatNames()));
    }

    public void loadUserContext(final UserContext userContext) {
        try {
            log.info("Does original image exist? {}", originalImage.exists());
            userContext.setRawOriginalImageBase64Encoded(convertImageToBase64(originalImage));
            userContext.setImageBytes(convertImageToByteArray(imageToEncrypt));
        } catch (final Exception e) {
            log.error("Could not load image", e);
        }
    }

    /**
     * Convert the image in the inImage to the format specified, and save to the outImage.
     * 
     * @param inImage the input image to convert
     * @param outImage the file resource to save the converted image to
     * @param format the foramt to convert to e.g. "JPEG".
     * 
     * @throws IOException on error to load, convert, or save the file
     */
    public void convertImageToFormat(final FileSystemResource inImage, final FileSystemResource outImage,
            final String format) throws IOException {
        log.debug("Saving {} to file: {}", format, outImage.getFilename());
        final BufferedImage image = ImageIO.read(inImage.getInputStream());
        ImageIO.write(image, format, outImage.getFile());

    }

    /**
     * Convert the input image bytes in assumed PPM format into the format given, and return as bytes.
     * 
     * @param imageBytes the image, in PPM format, to convert
     * @param format the format to convert to
     * 
     * @return the converted image in bytes
     * 
     * @throws IOException on error.
     */
    public byte[] convertImageToFormatInMemory(final byte[] imageBytes, final String format) throws IOException {
        log.debug("Converting image in-memory to format {}", format);
        final BufferedImage image = ImageIO.read(new ByteArrayImageInputStream(imageBytes));

        final ByteArrayOutputStream convertedImageStream = new ByteArrayOutputStream();
        ImageIO.write(image, format, convertedImageStream);
        convertedImageStream.close();

        return convertedImageStream.toByteArray();
    }

    /**
     * Combine the image body with the fixed image header, convert it in-memory to a JPEG and set the
     * rawEncryptedImageBase64Encoded value to the base64 of the JPEG version.
     * 
     * @param imageBytes the image body to save.
     */
    public void convertAndReloadEncrypted(final byte[] imageBytes, final UserContext userContext) {
        try {
            final byte[] combinedWithHeader = addHeaderToBytes(imageBytes);
            final byte[] convertedImage = convertImageToFormatInMemory(combinedWithHeader, "JPEG");
            userContext.setRawEncryptedImageBase64Encoded(new String(Base64.encodeBase64(convertedImage), "UTF-8"));

        } catch (final Exception e) {
            log.warn("Could not save image", e);
        }

    }

    /**
     * Combine the image body with the fixed image header, convert it in-memory to a JPEG and set the
     * rawDecryptedImageBase64Encoded value to the base64 of the JPEG version.
     * 
     * @param imageBytes the image body to save.
     */
    public void convertAndReloadDecrypted(final byte[] imageBytes, final UserContext userContext) {
        try {
            final byte[] combinedWithHeader = addHeaderToBytes(imageBytes);
            final byte[] convertedImage = convertImageToFormatInMemory(combinedWithHeader, "JPEG");
            userContext.setRawDecryptedImageBase64Encoded(new String(Base64.encodeBase64(convertedImage), "UTF-8"));

        } catch (final Exception e) {
            log.warn("Could not save image", e);
        }

    }

    /**
     * Adds the PPM header specific to the image body back to the image body to make a valid PPM file. The header was
     * stripped from the image on load (or a specific no header version was loaded), therefore the header is only
     * appropriate to the image loaded - although technically images of the same original format and size might work.
     * 
     * @param imageBody the body of the image (main image bitmap) without the header
     * 
     * @return the PPM header bytes added to the image body bytes
     * @throws IOException on error
     */
    public byte[] addHeaderToBytes(final byte[] imageBody) throws IOException {
        final byte[] header = PPM_HEADER.getBytes(StandardCharsets.UTF_8);
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            outputStream.write(header);
            outputStream.write(imageBody);
            return outputStream.toByteArray();
        }

    }

    /**
     * Read and return the file as bytes.
     * 
     * @param image the image to load
     * @return the image bytes
     * 
     * @throws FileNotFoundException on error
     * @throws IOException on error
     */
    public byte[] convertImageToByteArray(final Resource image) throws FileNotFoundException, IOException {

        final InputStream fileInputStreamReader = image.getInputStream();
        return IOUtils.toByteArray(fileInputStreamReader);
    }

    /**
     * Read the bytes in the file, and convert to a base64 string.
     * 
     * @param image the image to load
     * @return the base64 encoded version of the image
     * 
     * @throws FileNotFoundException on error
     * @throws IOException on error
     */
    public String convertImageToBase64(final Resource image) throws FileNotFoundException, IOException {
        String encodedfile = null;

        final InputStream fileInputStreamReader = image.getInputStream();
        final byte[] bytes = IOUtils.toByteArray(fileInputStreamReader);
        encodedfile = new String(Base64.encodeBase64(bytes), "UTF-8");

        return encodedfile;
    }

    public void resetImageEncryption(final UserContext userContext) {
        try {
            userContext.setImageBytes(convertImageToByteArray(imageToEncrypt));
            userContext.setRawEncryptedImageBase64Encoded(null);
            userContext.setRawDecryptedImageBase64Encoded(null);
        } catch (final Exception e) {
            log.error("Unable to reset tux image!", e);
        }

    }

}
