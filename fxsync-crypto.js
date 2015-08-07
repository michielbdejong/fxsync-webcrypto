// WebCrypto-based client for Firefox Sync.
// Requires hawk_creds.js from https://github.com/mozilla-b2g/firefoxos-loop-client/

(function(window) {
  // FIXME: Discuss whether documentation on
  // http://docs.services.mozilla.com/sync/storageformat5.html
  // should be updated to mention that this is the string to use:
  const HKDF_INFO_STR = 'identity.mozilla.com/picl/v1/oldsync';
 
  // constructor
  window.FxSyncWebCrypto = function() {
    // Basic check for presence of WebCrypto
    if (!window || !window.crypto || !window.crypto.subtle) {
      throw new Error('This environment does not support WebCrypto');
    }

    this.mainSyncKey = null;
    this.syncKeys = null;
  };

  // Conversion functions:
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
  function importKeyBundle(aesKeyAB, hmacKeyAB) {
    var pAes = window.crypto.subtle.importKey('raw', aesKeyAB,
                                          { name: 'AES-CBC', length: 256 },
                                          true, [ 'encrypt', 'decrypt' ]
                                    );
    var pHmac =  window.crypto.subtle.importKey('raw', hmacKeyAB,
                                          { name: 'HMAC', hash: 'SHA-256' },
                                          true, [ 'verify' ]
                                      );
    console.log('ps', pAes, pHmac);
    return Promise.all([pAes, pHmac]).then(function(results) {
      console.log('iterator results', results);
      return {
        aes: results[0],
        hmac: results[1]
      };
    });
  }
  window.FxSyncWebCrypto.prototype._importKb = function(kBByteArray) {
    // The number 64 here comes from (256 bits for AES + 256 bits for HMAC) / (8 bits per byte)
    return window.hawkCredentials.then(function(hC) {    
      return hC.hkdf(kBByteArray, rawStringToByteArray(HKDF_INFO_STR), new Uint8Array(64), 64);
    }).then(function (output) {
      var aesKeyAB = output.slice(0, 32).buffer;
      var hmacKeyAB = output.slice(32).buffer;
      return importKeyBundle(aesKeyAB, hmacKeyAB).then(function(keyBundle) {
        console.log('keyBundle', keyBundle)
        this.mainSyncKey = keyBundle;
      }.bind(this), function(err) { console.log('err', err);});
    }.bind(this));
  };

  window.FxSyncWebCrypto.prototype._verifySyncKeys = function(syncKeysIVByteArray,
                                                                syncKeysCiphertextByteArray,
                                                                syncKeysHmacByteArray) {
    console.log(this);
    return crypto.subtle.verify(/*{ name: */'HMAC'/*, hash: 'AES-256' }*/, this.mainSyncKey.hmac,
                          syncKeysHmacByteArray, syncKeysCiphertextByteArray).then(function (verification) {
      console.log('verification', verification);
    }.bind(this), function(err) {
      console.log('error verifying syncKeys using kB', err);
      return Promise.reject('Could not verify crypto keys using HMAC part of stretched kB key');
    });
  }
  
  window.FxSyncWebCrypto.prototype._importSyncKeys = function(syncKeysIVByteArray,
                                                                syncKeysCiphertextByteArray,
                                                                syncKeysHmacByteArray) {
    console.log(this);
    return crypto.subtle.decrypt({ name: 'AES-CBC', iv: syncKeysIVByteArray }, this.mainSyncKey.aes,
                          syncKeysCiphertextByteArray).then(function (keyBundleAB) {
      console.log('keyBundleAB', keyBundleAB);
      console.log('keyBundleStr', String.fromCharCode.apply(null, new Uint8Array(keyBundleAB)));
      var syncKeysJSON = String.fromCharCode.apply(null, new Uint8Array(keyBundleAB));
      try {
        this.syncKeys = JSON.parse(syncKeysJSON);
        return importKeyBundle(
            base64StringToByteArray(this.syncKeys.default[0]),
            base64StringToByteArray(this.syncKeys.default[1])
        ).then(function(keyBundle) {
          console.log('imported default key bundle', keyBundle);
          this.syncKeys.defaultAsKeyBundle = keyBundle;
        }.bind(this));
        console.log('imported', this);
      } catch(e) {
        return Promise.reject('Deciphered crypto keys, but not JSON');
      }
    }.bind(this), function(err) {
      return Promise.reject('Could not decrypt crypto keys using AES part of stretched kB key');
    });
  }

  /*
   * setKeys
   */
  window.FxSyncWebCrypto.prototype.setKeys = function(kB, syncKeys) {
    var kBByteArray, syncKeysCiphertextByteArray, syncKeysIVByteArray, syncKeysHmacByteArray;

    // Input checking
    try {
      kBByteArray = hexStringToByteArray(kB);
    } catch (e) {
      console.log('error reading hex kB', e);
      return Promise.reject('Could not parse kB as a hex string');
    }
    try {
      syncKeysCiphertextByteArray = base64StringToByteArray(syncKeys.ciphertext);
    } catch (e) {
      return Promise.reject('Could not parse syncKeysCiphertext as a base64 string');
    }
    try {
      syncKeysIVByteArray = base64StringToByteArray(syncKeys.IV);
    } catch (e) {
      return Promise.reject('Could not parse syncKeysIV as a base64 string');
    }
    try {
      syncKeysHmacByteArray = hexStringToByteArray(syncKeys.hmac);
    } catch (e) {
      return Promise.reject('Could not parse syncKeysHmac as a hex string');
    }

    return this._importKb(kBByteArray).then(function() {
      console.log('kB imported', this);
      return this._verifySyncKeys(syncKeysIVByteArray, syncKeysCiphertextByteArray,
                                                  syncKeysHmacByteArray);
    }.bind(this)).then(function() {
      console.log('kB imported', this);
      return this._importSyncKeys(syncKeysIVByteArray, syncKeysCiphertextByteArray,
                                                  syncKeysHmacByteArray);
    }.bind(this));
  }
  
  window.FxSyncWebCrypto.prototype.selectKeyBundle = function() {
    return this.syncKeys.defaultAsKeyBundle;
  }

  window.FxSyncWebCrypto.prototype.verifyAndDecryptRecord = function(payload, collectionName) {
    var record, keyBundle;
    try {
      recordEnc = JSON.parse(payload);
    } catch(e) {
      return Promise.reject('Payload is not a JSON string');
    }
    try {
      keyBundle = this.selectKeyBundle(collectionName);
    } catch(e) {
      return Promise.reject('No key bundle found for ' + collectionName + ' - did you call setKeys?');
    }
    console.log('using this key bundle', keyBundle);
    return crypto.subtle.verify({ name: 'HMAC', hash: 'SHA-256' },
                                keyBundle.hmac, base64StringToByteArray(recordEnc.hmac),
                                base64StringToByteArray(recordEnc.ciphertext)
                               ).then(function (result) {
      if (!result) {
        //return Promise.reject('Record verification failed with current hmac key for ' + collectionName);
      }
    }).then(function() {
      return crypto.subtle.decrypt({
        name: 'AES-CBC',
        iv: base64StringToByteArray(recordEnc.IV)
      }, keyBundle.aes, base64StringToByteArray(recordEnc.ciphertext)).then(function (recordArrayBuffer) {
        var recordObj;
        var recordJSON = String.fromCharCode.apply(null, new Uint8Array(recordArrayBuffer));
        try {
          recordObj = JSON.parse(recordJSON);
        } catch(e) {
          return Promise.reject('Deciphered record, but not JSON');
        }
        return recordObj;
      }, function(err) {
        return Promise.reject('Could not decrypt record using AES part of key bundle for collection ' + collectionName);
      });
    });
  }
})(window);
