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
	// nonce=iv which is a byte between 0 and 255 (00000000 and 11111111). The IV MUST normally
	// Change for each enc operation, so this is flawed.
	var nonce = 100;
	// Use the block index as the counter (does not need previous block, so parallelizable)
	for (var i = 0; i < messageAsBytes.length; i = i + blockSize) {
		messageAsBytes[i] = i ^ nonce ^ messageAsBytes[i] ^ keyAsBytes[0];
	}
	return messageAsBytes;
}


// Often the same operation to decrypt as encrypt when XOR is involved
var decodedMessageAsBytes = function decrypt(encryptedMessageAsBytes, keyAsBytes, decryptedArray) {
	if (encryptedMessageAsBytes.length % keyAsBytes.length != 0) {
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
	var nonce = 100;
	for (var i = 0; i < encryptedMessageAsBytes.length; i = i + blockSize) {		
		decryptedArray[i] = i ^ nonce ^ encryptedMessageAsBytes[i] ^ keyAsBytes[0];

	}
	return decryptedArray;
}
