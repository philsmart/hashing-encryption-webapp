var cipherTextAsBytes = function encrypt(message, keyAsBytes) {
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
	var bytes = message.getBytes();
	for (var i = 0; i < bytes.length; i = i + 1) {
		print("Before " + bytes[i]);
		var b = bytes[i] + shift;
		bytes[i] = b;
		print("After: " + UInt8(bytes[i]));

	}
	return bytes;
}



var decodedMessage = function decrypt(messageAsBytes, keyAsBytes) {
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
	var str = '';
	for (var i = 0; i < messageAsBytes.length; i = i + 1) {
		print("Before " + UInt8(messageAsBytes[i]));
		var decryptedByte = messageAsBytes[i] - shift;
		print("After: " + UInt8(decryptedByte));
		str += String.fromCharCode(decryptedByte);
	}
	print("Decrypted:" + str);
	return str;
}

var UInt8 = function(value) {
	return (value & 0xFF);
};