var cipherTextAsBytes = function encrypt(message, keyAsBytes){
   var bytes = message.getBytes();
   if (message.getBytes().length % keyAsBytes.length != 0){
      print("Key incompatible");
      return "".getBytes();
   }
   for (var i=0; i<bytes.length; i=i+keyAsBytes.length) {
        for (var j = 0; j < keyAsBytes.length; j++){
           print("Before " + bytes[i]);
           var b = bytes[i+j] ^ keyAsBytes[j];        
           bytes[i+j] = b;
           print("After: " + UInt8(bytes[i]));
        }
    }    
    return bytes;
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