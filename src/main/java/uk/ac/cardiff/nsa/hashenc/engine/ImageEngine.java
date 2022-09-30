package uk.ac.cardiff.nsa.hashenc.engine;

import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import javax.imageio.ImageIO;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

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
	private final Resource originalImage = new ClassPathResource("tux.png");

	/** The base64 version of the image to show before encryption. */
	private String rawOriginalImageBase64Encoded;

	/** The raw bytes of the save encrypted imaged. */
	private String rawEncryptedImageBase64Encoded;

	/**
	 * The raw bytes of the uncompressed, unencrypted image, without the header,
	 * ready for encryption.
	 */
	private byte[] imageBytes;

	public ImageEngine() {
		log.info("ImageIO suports '{}'", Arrays.asList(ImageIO.getReaderFormatNames()));
		try {
			imageBytes = convertImageToByteArray(imageToEncrypt);
			
			//Testing
			saveImageConvertAndReload(imageBytes, new FileSystemResource("enc-load.ppm"));
			
			rawOriginalImageBase64Encoded = convertImageToBase64(originalImage);			
		} catch (Exception e) {
			log.error("Could not load image", e);
		}

	}

	public void convertImageToFormat(FileSystemResource inImage, FileSystemResource outImage, String format)
			throws IOException {
		log.debug("Saving {} to file: {}", format, outImage.getFilename());
		BufferedImage image = ImageIO.read(inImage.getInputStream());
		ImageIO.write(image, format, outImage.getFile());

	}

	/**
	 * Get a defensive copy of the loaded image (body only, no header) bytes.
	 * 
	 * @return the image body as bytes
	 */
	public byte[] getImageBytes() {
		return Arrays.copyOf(imageBytes, imageBytes.length);
	}

	public void saveImageConvertAndReload(byte[] imageBytes, FileSystemResource saveFile) {
		try {
			byte[] combinedWithHeader = addHeaderToBytes(imageBytes);
			try (OutputStream out = saveFile.getOutputStream()) {
				out.write(combinedWithHeader);
			}
			// TODO base on save file but with .jpeg
			FileSystemResource newFile = new FileSystemResource(saveFile.getFilename().replace("ppm", "jpg"));
			convertImageToFormat(saveFile, newFile, "JPEG");

			rawEncryptedImageBase64Encoded = convertImageToBase64(newFile);

		} catch (Exception e) {
			log.warn("Could not save image", e);
		}

	}

	/**
	 * Adds the PPM header specific to the image body back to the image body to make
	 * a valid PPM file. The header was stripped from the image on load (or a
	 * specific no header version was loaded), therefore the header is only
	 * appropriate to the image loaded - although technically images of the same
	 * original format and size might work.
	 * 
	 * @param imageBody the body of the image (main image bitmap) without the header
	 * 
	 * @return the PPM header bytes added to the image body bytes
	 * @throws IOException on error
	 */
	public byte[] addHeaderToBytes(final byte[] imageBody) throws IOException {
		byte[] header = PPM_HEADER.getBytes(StandardCharsets.UTF_8);
		try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
			outputStream.write(header);
			outputStream.write(imageBytes);
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
	 * @throws IOException           on error
	 */
	public byte[] convertImageToByteArray(Resource image) throws FileNotFoundException, IOException {

		FileInputStream fileInputStreamReader = new FileInputStream(image.getFile());
		byte[] bytes = new byte[(int) image.getFile().length()];
		fileInputStreamReader.read(bytes);
		return bytes;
	}

	/**
	 * Read the bytes in the file, and convert to a base64 string.
	 * 
	 * @param image the image to load
	 * @return the base64 encoded version of the image
	 * 
	 * @throws FileNotFoundException on error
	 * @throws IOException           on error
	 */
	public String convertImageToBase64(Resource image) throws FileNotFoundException, IOException {
		String encodedfile = null;

		FileInputStream fileInputStreamReader = new FileInputStream(image.getFile());
		byte[] bytes = new byte[(int) image.getFile().length()];
		fileInputStreamReader.read(bytes);
		encodedfile = new String(Base64.encodeBase64(bytes), "UTF-8");

		return encodedfile;
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

}
