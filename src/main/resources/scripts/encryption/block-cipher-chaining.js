var cipherTextAsBytes = function encrypt(messageAsBytes, keyAsBytes) {
	if (messageAsBytes.length % keyAsBytes.length != 0) {
		print("Key incompatible");
		return "".getBytes();
	}
	var blockSize = keyAsBytes.length;
	for (var i = 0; i < messageAsBytes.length; i = i + blockSize) {
		for (var j = 0; j < blockSize; j++) {
			var b = messageAsBytes[i + j] ^ keyAsBytes[j];
			messageAsBytes[i + j] = b;
		}
		if (i >= blockSize) {
			for (var j = 0; j < blockSize; j++) {
				var b = messageAsBytes[(i - blockSize) + j] ^ messageAsBytes[i + j];
				messageAsBytes[i + j] = b;
			}
		}

	}
	return messageAsBytes;
}

var decodedMessage = function decrypt(messageAsBytes, keyAsBytes) {
	if (messageAsBytes.length % keyAsBytes.length != 0) {
		print("Key incompatible");
		return "".getBytes();
	}
	var blockSize = keyAsBytes.length;
	var str = '';
	for (var i = 0; i < messageAsBytes.length; i = i + blockSize) {
		for (var j = 0; j < blockSize; j++) {
			var decryptedByte = messageAsBytes[i + j] ^ keyAsBytes[j];
			str += String.fromCharCode(decryptedByte);
		}
		if (i >= blockSize) {
			for (var j = 0; j < blockSize; j++) {
				var b = messageAsBytes[(i - blockSize) + j] ^ messageAsBytes[i + j];
				messageAsBytes[i + j] = b;
			}
		}
	}

	return str;
}

var UInt8 = function(value) {
	return (value & 0xFF);
};