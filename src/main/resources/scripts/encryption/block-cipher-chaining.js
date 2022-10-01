var cipherTextAsBytes = function encrypt(messageAsBytes, keyAsBytes) {
	if (messageAsBytes.length % keyAsBytes.length != 0) {
		print("Key incompatible");
		return "".getBytes();
	}
	if (keyAsBytes.length != 1) {
		print("Key incompatible, only support 8 bit keys");
		return "".getBytes();
	}
	// 8 bit keys, so fix the block to 8 bits or 1 byte, so byte for byte
	var blockSize = 1;
	// IV is a byte between 0 and 255 (00000000 and 11111111). The IV MUST normally
	// Change for each enc operation, so this is flawed.
	var iv = 100;
	for (var i = 0; i < messageAsBytes.length; i = i + blockSize) {
		if (i == 0){
			// First block you mix (XOR) with the IV so same starting blocks give different cipher texts
			var b = messageAsBytes[i] ^ keyAsBytes[0] ^ iv;
			messageAsBytes[i] = b;
		} else{
			// Then XOR current plaintext with previous cipher text with key
			var b = keyAsBytes[0] ^ (messageAsBytes[i]) ^ messageAsBytes[i-1];
			messageAsBytes[i] = b;
		}
	}
	return messageAsBytes;
}


// Often the same operation to decrypt as encrypt when XOR is involved
var decodedMessageAsBytes = function decrypt(messageAsBytes, keyAsBytes, decryptedArray) {
	if (messageAsBytes.length % keyAsBytes.length != 0) {
		print("Key incompatible");
		return "".getBytes();
	}
	if (keyAsBytes.length != 1) {
		print("Key incompatible, only support 8 bit keys");
		return "".getBytes();
	}
	// 8 bit keys, so fix the block to 8 bits or 1 byte, so byte for byte
	var blockSize = 1;
	// Here is the IV again - the same as for encryption - is not secret.
	var iv = 100;
	for (var i = 0; i < messageAsBytes.length; i = i + blockSize) {
		if (i == 0){
			var b = messageAsBytes[i] ^ keyAsBytes[0] ^ iv;
			decryptedArray[i] = b;
		} else{
			// XOR current ciphertext with previous cipher text with key
			var b =  keyAsBytes[0] ^ (messageAsBytes[i]) ^ messageAsBytes[i-1];
			decryptedArray[i] = b;
		}
	}
	return decryptedArray;
}
