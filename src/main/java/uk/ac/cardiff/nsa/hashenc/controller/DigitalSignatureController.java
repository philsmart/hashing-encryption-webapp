
package uk.ac.cardiff.nsa.hashenc.controller;

import java.util.Arrays;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import uk.ac.cardiff.nsa.hashenc.context.UserDigitalSignatureContext;
import uk.ac.cardiff.nsa.hashenc.context.UserEncryptionContext;
import uk.ac.cardiff.nsa.hashenc.engine.HashEngine;
import uk.ac.cardiff.nsa.hashenc.engine.JWTUtils;

/**
 * Basic Digital Signature controller.
 */
@Controller
@SessionAttributes("userDigitalSignatureContext")
public class DigitalSignatureController {

	/** Class logger. */
	private final Logger log = LoggerFactory.getLogger(DigitalSignatureController.class);

	private final String TEMPLATE_JSON = """
			{
				"first_name": "John",
				"Surname": "Doe",
				"role" : "user"
			}
			""";

	/** Constructor. */
	public DigitalSignatureController() {

	}

	/**
	 * Allow spring to create a UserContext and place it inside the HTTP Session for
	 * use by the user (JSESSIONID) of this application.
	 * 
	 * @return the user context.
	 */
	@ModelAttribute("userDigitalSignatureContext")
	public UserDigitalSignatureContext constructUserContext() {
		final UserDigitalSignatureContext userContext = new UserDigitalSignatureContext();

		var key = "examplekey";

		String compactHeaderPayload = JWTUtils.createJWTCompactSerlizationForSigning(JWTUtils.DEFAULT_JOSE_HEADER,
				TEMPLATE_JSON);
		final byte[] mac = HashEngine.constructHmacAsBytes(compactHeaderPayload, key);

		userContext.setPayload(TEMPLATE_JSON);
		userContext.setSignature(mac);
		userContext.setKey(key);
		userContext.setHeader(JWTUtils.DEFAULT_JOSE_HEADER);
		return userContext;
	}

	@PostMapping(value = "/hmac-payload", params = "action=compute")
	public String hmacPayload(@RequestParam("payload") final String payload,
			@RequestParam("header") final String header, @RequestParam("key") final String key,
			final RedirectAttributes model,
			@ModelAttribute("userDigitalSignatureContext") final UserDigitalSignatureContext userCtx) {

		String compactHeaderPayload = JWTUtils.createJWTCompactSerlizationForSigning(header, payload);

		final byte[] mac = HashEngine.constructHmacAsBytes(compactHeaderPayload, key);
		userCtx.setPayload(payload);
		userCtx.setHeader(header);

		model.addFlashAttribute("mac", Base64.encodeBase64URLSafeString(mac));
		model.addFlashAttribute("jwtCompact", JWTUtils.appendSignature(compactHeaderPayload, mac));
		return "redirect:sig";
	}

	@PostMapping(value = "/hmac-payload", params = "action=check")
	public String verifyPayload(@RequestParam("payload") final String payload,
			@RequestParam("header") final String header, @RequestParam("existingMac") final String existingMac,
			final RedirectAttributes model,
			@ModelAttribute("userDigitalSignatureContext") final UserDigitalSignatureContext userCtx) {

		userCtx.setPayload(payload);
		userCtx.setHeader(header);
		byte[] macFromInput = Base64.decodeBase64(existingMac);
		userCtx.setSignature(macFromInput);
		String compactHeaderPayload = JWTUtils.createJWTCompactSerlizationForSigning(header, payload);
		final byte[] mac = HashEngine.constructHmacAsBytes(compactHeaderPayload, userCtx.getKey());

		model.addFlashAttribute("verified", Arrays.equals(mac, macFromInput));
		return "redirect:sig";
	}

	/**
	 * Get the 'digital-signatures' page and set suitable model values.
	 * 
	 * @param model the model to return
	 * 
	 * @return the 'digital-signatures.html' page
	 */
	@GetMapping("/sig")
	public String getEncryptionPage(final Model model,
			@ModelAttribute("userDigitalSignatureContext") final UserDigitalSignatureContext userCtx) {

		model.addAttribute("payload", userCtx.getPayload());
		model.addAttribute("existingMac", Base64.encodeBase64URLSafeString(userCtx.getSignature()));
		model.addAttribute("header", userCtx.getHeader());
		model.addAttribute("key", userCtx.getKey());
		if (model.getAttribute("verified") == null) {
			String compactHeaderPayload = JWTUtils.createJWTCompactSerlizationForSigning(userCtx.getHeader(),
					userCtx.getPayload());
			final byte[] mac = HashEngine.constructHmacAsBytes(compactHeaderPayload, userCtx.getKey());
			model.addAttribute("verified", Arrays.equals(mac, userCtx.getSignature()));
		}
		return "digital-signatures";
	}

}
