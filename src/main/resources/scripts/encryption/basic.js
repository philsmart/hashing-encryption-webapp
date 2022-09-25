var cipherTextAsBytes = function encrypt(message, keyAsBytes){
   return message.getBytes();
}

var decodedMessage = function decrypt(messageAsBytes, key){
   var str = '';
   for (var i=0; i<messageAsBytes.length; ++i) {
	str+= String.fromCharCode(messageAsBytes[i]);
    }
   return str;
}