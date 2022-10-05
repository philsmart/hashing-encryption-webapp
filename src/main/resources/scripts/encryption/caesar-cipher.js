// Note, a Caesar cipher would not normally operate over a generic set of bytes like
// it is here. So this is not a true Caesar Cipher. It simply shifts (increments) the 
// number corresponding to the byte by the shift, and does not wrap around if that byte no 
// longer represents an alphanumeric e.g. Z plus a shift of 1 will give the UTF-8 (and ASCII) 
// character of '{' and not 'a' as it should.

var cipherTextAsBytes = function encrypt(messageAsBytes, keyAsBytes) {
	if (keyAsBytes.length > 1) {
		print("Caesar cipher key should be 1 byte");
		return "".getBytes();
	}
	// Convert key to int shift
	var shift = 0;
	for (var i = keyAsBytes.length - 1; i >= 0; i--) {
		shift = (shift * 256) + keyAsBytes[i];
	}
	if (shift > 4) {
		print("Caesar cipher shift is limited to max 4");
		return "".getBytes();
	}
	print("Shift: " + shift);
	for (var i = 0; i < messageAsBytes.length; i = i + 1) {
		var b = messageAsBytes[i] + shift;
		messageAsBytes[i] = b;
	}
	return messageAsBytes;
}



var decodedMessageAsBytes = function decrypt(encryptedMessageAsBytes, keyAsBytes, decryptedArray) {
	if (keyAsBytes.length > 1) {
		print("Caesar cipher key should be 1 byte");
		return "".getBytes();
	}
	// Convert key to int shift
	var shift = 0;
	for (var i = keyAsBytes.length - 1; i >= 0; i--) {
		shift = (shift * 256) + keyAsBytes[i];
	}
	if (shift > 4) {
		print("Caesar cipher shift is limited to max 4");
		return "".getBytes();
	}
	print("Shift back: " + shift);
	for (var i = 0; i < encryptedMessageAsBytes.length; i = i + 1) {
	    decryptedArray[i] = encryptedMessageAsBytes[i] - shift;
	}
	return decryptedArray;
}
