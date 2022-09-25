var cipherTextAsBytes = function encrypt(message, keyAsBytes){
   var bytes = message.getBytes();
   if (message.getBytes().length!=keyAsBytes.length){
      print("Key incompatible");
      return "".getBytes();
   }
   for (var i=0; i<bytes.length; ++i) {
        print("Before " + bytes[i]);
        var b = bytes[i] ^ keyAsBytes[i];        
        bytes[i] = b;
        print("After: " + UInt8(bytes[i]));
    }    
    return bytes;
}

var decodedMessage = function decrypt(messageAsBytes, keyAsBytes){
   if (messageAsBytes.length!=keyAsBytes.length){
      print("Key incompatible");
      return "".getBytes();
   }
   var str = '';
   for (var i=0; i < messageAsBytes.length; ++i) {
        // convert signed int in the byte to unsigned before XOR
        var decryptedByte = UInt8(messageAsBytes[i]) ^ UInt8(keyAsBytes[i]);
        str+= String.fromCharCode(decryptedByte);
        
    }

   return str;
}

var UInt8 = function (value) {
    return (value & 0xFF);
};