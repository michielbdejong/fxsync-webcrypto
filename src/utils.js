function rawStringToByteArray(str) {
  var strLen = str.length;
  var byteArray = new Uint8Array(strLen);
  for (var i = 0, strLen; i < strLen; i++) {
    byteArray[i] = str.charCodeAt(i);
  }
  return byteArray;
}

function base64StringToByteArray(base64) {
  if (typeof base64 != 'string' || base64.length % 4 !== 0) {
    throw Error('Number of base64 digits must be a multiple of 4 to convert to bytes');
  }
  return rawStringToByteArray(window.atob(base64));
}

function hexStringToByteArray(hexStr) {
  if (typeof hexStr != 'string' || hexStr.length % 2 !== 0) {
    throw Error('Must have an even number of hex digits to convert to bytes');
  }
  var numBytes = hexStr.length / 2;
  var byteArray = new Uint8Array(numBytes);
  for (var i = 0; i < numBytes; i++) {
    byteArray[i] = parseInt(hexStr.substr(i * 2, 2), 16); //FIXME: Can this be done faster?
  }
  return byteArray;
}

function arrayBufferToBase64String(buffer) {
  var binary = '';
  var bytes = new Uint8Array(buffer);
  var len = bytes.byteLength;
  for (var i=0; i<len; i++) {
      binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

function arrayBufferToHexString(buffer) {
  var hexChars = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'];
  var hex = '';
  var bytes = new Uint8Array(buffer);
  var len = bytes.byteLength;
  for (var i=0; i<len; i++) {
    hex += hexChars[Math.floor(bytes[i]/16)] + hexChars[bytes[i]%16];
  }
  return hex;
}

//...
window.rawStringToByteArray = rawStringToByteArray;
window.base64StringToByteArray = base64StringToByteArray;
window.hexStringToByteArray = hexStringToByteArray;
window.arrayBufferToBase64String = arrayBufferToBase64String;
window.arrayBufferToHexString = arrayBufferToHexString;
