var cipherTextAsBytes = function encrypt(messageAsBytes, keyAsBytes){
   if (messageAsBytes.length % keyAsBytes.length != 0){
      print("Key incompatible");
      return "".getBytes();
   }
   for (var i=0; i<messageAsBytes.length; i=i+keyAsBytes.length) {
		// Usually much more happens during each 'block' enc. step e.g. see SP networks
        for (var j = 0; j < keyAsBytes.length; j++){
           messageAsBytes[i+j] = messageAsBytes[i+j] ^ keyAsBytes[j];        
        }
    }    
    return messageAsBytes;
}

var decodedMessageAsBytes = function decrypt(encryptedMessageAsBytes, keyAsBytes, decryptedArray){
   if (encryptedMessageAsBytes.length % keyAsBytes.length != 0){
      print("Key incompatible");
      return "".getBytes();
   }
   for (var i=0; i<encryptedMessageAsBytes.length; i=i+keyAsBytes.length) {
        for (var j = 0; j < keyAsBytes.length; j++){
           decryptedArray[i+j] = encryptedMessageAsBytes[i+j] ^ keyAsBytes[j];     
        }
    } 
   return decryptedArray;
}