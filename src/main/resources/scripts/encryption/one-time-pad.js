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

var decodedMessageAsBytes = function decrypt(messageAsBytes, keyAsBytes, decryptedArray){
   if (messageAsBytes.length!=keyAsBytes.length){
      print("Key incompatible");
      return "".getBytes();
   }
   for (var i=0; i < messageAsBytes.length; ++i) {
        // convert signed int in the byte to unsigned before XOR
        decryptedArray[i] = UInt8(messageAsBytes[i]) ^ UInt8(keyAsBytes[i]);
        
    }
   return decryptedArray;
}

var UInt8 = function (value) {
    return (value & 0xFF);
};