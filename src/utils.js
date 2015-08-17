var StringConversion = {
  rawStringToByteArray: function(str) {
    if (typeof str != 'string') {
      throw new Error('Not a string');
    }
    var strLen = str.length;
    var byteArray = new Uint8Array(strLen);
    for (var i = 0, strLen; i < strLen; i++) {
      byteArray[i] = str.charCodeAt(i);
    }
    return byteArray;
  },
  
  base64StringToByteArray: function(base64) {
    if (typeof base64 != 'string' || base64.length % 4 !== 0) {
      throw new Error('Number of base64 digits must be a multiple of 4 to convert to bytes');
    }
    return this.rawStringToByteArray(window.atob(base64));
  },
  
  hexStringToByteArray: function(hexStr) {
    if (typeof hexStr != 'string' || hexStr.length % 2 !== 0) {
      throw new Error('Must have an even number of hex digits to convert to bytes');
    }
    var numBytes = hexStr.length / 2;
    var byteArray = new Uint8Array(numBytes);
    for (var i = 0; i < numBytes; i++) {
      byteArray[i] = parseInt(hexStr.substr(i * 2, 2), 16); //FIXME: Can this be done faster?
    }
    return byteArray;
  },
  
  byteArrayToBase64String: function(bytes) {
    var binary = '';
    var len = bytes.byteLength;
    for (var i=0; i<len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  },
  
  arrayBufferToBase64String: function(buffer) {
    if (!(buffer instanceof ArrayBuffer)) {
      console.log('oops', buffer);
      throw new Error('Not an ArrayBuffer');
    }
    var bytes = new Uint8Array(buffer);
    return this.byteArrayToBase64String(bytes);
  },
  
  byteArrayToHexString: function(bytes) {
    var hex = '';
    for (var i=0; i <bytes.length; ++i) {
      var zeropad = (bytes[i] < 0x10) ? "0" : "";
      hex += zeropad + bytes[i].toString(16);
    }
    return hex;
  },

  arrayBufferToHexString: function(buffer) {
    if (!(buffer instanceof ArrayBuffer)) {
      throw new Error('Not an ArrayBuffer');
    }
    var bytes = new Uint8Array(buffer);
    return this.byteArrayToHexString(bytes);
  }

};
