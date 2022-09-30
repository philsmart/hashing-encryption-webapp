var cipherTextAsBytes = function encrypt(messageAsBytes, keyAsBytes){
   if (messageAsBytes.length % keyAsBytes.length != 0){
      print("Key incompatible");
      return "".getBytes();
   }
   for (var i=0; i<messageAsBytes.length; i=i+keyAsBytes.length) {
        for (var j = 0; j < keyAsBytes.length; j++){
           var b = messageAsBytes[i+j] ^ keyAsBytes[j];        
           messageAsBytes[i+j] = b;
        }
    }    
    return messageAsBytes;
}

var decodedMessage = function decrypt(messageAsBytes, keyAsBytes){
   if (messageAsBytes.length % keyAsBytes.length != 0){
      print("Key incompatible");
      return "".getBytes();
   }
   var str = '';
   for (var i=0; i<messageAsBytes.length; i=i+keyAsBytes.length) {
        for (var j = 0; j < keyAsBytes.length; j++){
           var decryptedByte = messageAsBytes[i+j] ^ keyAsBytes[j];        
           str+= String.fromCharCode(decryptedByte);
        }
    } 

   return str;
}

var UInt8 = function (value) {
    return (value & 0xFF);
};