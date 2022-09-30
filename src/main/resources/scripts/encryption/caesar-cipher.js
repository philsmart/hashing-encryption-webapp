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



var decodedMessageAsBytes = function decrypt(messageAsBytes, keyAsBytes) {
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
	for (var i = 0; i < messageAsBytes.length; i = i + 1) {
		var decryptedByte = messageAsBytes[i] - shift;
		messageAsBytes[i] = decryptedByte;
	}
	return messageAsBytes;
}

var UInt8 = function(value) {
	return (value & 0xFF);
};