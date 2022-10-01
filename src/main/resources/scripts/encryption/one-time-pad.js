var cipherTextAsBytes = function encrypt(messageAsBytes, keyAsBytes){
   if (messageAsBytes.length!=keyAsBytes.length){
      print("Key incompatible");
      return "".getBytes();
   }
   for (var i=0; i<messageAsBytes.length; ++i) {       
        var b = messageAsBytes[i] ^ keyAsBytes[i];        
        messageAsBytes[i] = b;
    }    
    return messageAsBytes;
}

var decodedMessageAsBytes = function decrypt(encryptedMessageAsBytes, keyAsBytes, decryptedArray){
   if (encryptedMessageAsBytes.length!=keyAsBytes.length){
      print("Key incompatible");
      return "".getBytes();
   }
   for (var i=0; i < encryptedMessageAsBytes.length; ++i) {
        decryptedArray[i] = encryptedMessageAsBytes[i] ^ keyAsBytes[i];
        
    }
   return decryptedArray;
}