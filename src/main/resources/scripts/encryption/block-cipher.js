var cipherTextAsBytes = function encrypt(messageAsBytes, keyAsBytes){
   if (messageAsBytes.length % keyAsBytes.length != 0){
      print("Key incompatible");
      return "".getBytes();
   }
   for (var i=0; i<messageAsBytes.length; i=i+keyAsBytes.length) {
		// Usually much more happens during each 'block' enc. step e.g. see SP networks
        for (var j = 0; j < keyAsBytes.length; j++){
           var b = messageAsBytes[i+j] ^ keyAsBytes[j];        
           messageAsBytes[i+j] = b;
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
           var decryptedByte = encryptedMessageAsBytes[i+j] ^ keyAsBytes[j]; 
           decryptedArray[i+j] = decryptedByte;    
        }
    } 
   return decryptedArray;
}