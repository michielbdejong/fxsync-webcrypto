/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// WebCrypto-based client for Firefox Sync.

const HKDF_INFO_STR = 'identity.mozilla.com/picl/v1/oldsync';

// constructor
var FxSyncWebCrypto = function() {
  // Basic check for presence of WebCrypto
  if (!exports || !exports.crypto || !exports.crypto.subtle) {
    throw new Error('This environment does not support WebCrypto');
  }

  this.mainSyncKey = null;
  this.bulkKeyBundle = null;
};

function importKeyBundle(aesKeyAB, hmacKeyAB) {
  var pAes = exports.crypto.subtle.importKey('raw', aesKeyAB,
                                        { name: 'AES-CBC', length: 256 },
                                        true, [ 'encrypt', 'decrypt' ]
                                  );
  var pHmac =  exports.crypto.subtle.importKey('raw', hmacKeyAB,
                                        { name: 'HMAC', hash: 'SHA-256' },
                                        true, [ 'sign', 'verify' ]
                                    );
  return Promise.all([pAes, pHmac]).then(function(results) {
    return {
      aes: results[0],
      hmac: results[1]
    };
  });
}
FxSyncWebCrypto.prototype._importKb = function(kBByteArray) {
  // The number 64 here comes from
  // (256 bits for AES + 256 bits for HMAC) / (8 bits per byte)
  return KeyDerivation.hkdf(kBByteArray,
      StringConversion.rawStringToByteArray(HKDF_INFO_STR), new Uint8Array(64),
      64).then(function (output) {
    var aesKeyAB = output.slice(0, 32).buffer;
    var hmacKeyAB = output.slice(32).buffer;
    return importKeyBundle(aesKeyAB, hmacKeyAB).then(function(keyBundle) {
      this.mainSyncKey = keyBundle;
    }.bind(this));
  }.bind(this));
};

FxSyncWebCrypto.prototype._verifySyncKeys = function(signedTextByteArray,
    cryptoKeysHmacByteArray) {
  return crypto.subtle.verify({ name: 'HMAC', hash: 'AES-256' },
      this.mainSyncKey.hmac, cryptoKeysHmacByteArray, signedTextByteArray);
};

FxSyncWebCrypto.prototype._importSyncKeys = function(cryptoKeysIVByteArray,
   cryptoKeysCiphertextByteArray) {
  return crypto.subtle.decrypt({ name: 'AES-CBC', iv: cryptoKeysIVByteArray },
      this.mainSyncKey.aes,
      cryptoKeysCiphertextByteArray).then(function(keyBundleAB) {
    var cryptoKeysJSON = String.fromCharCode.apply(null,
        new Uint8Array(keyBundleAB));
    try {
      this.bulkKeyBundle = JSON.parse(cryptoKeysJSON);
      return importKeyBundle(
          StringConversion.base64StringToByteArray(
              this.bulkKeyBundle.default[0]),
          StringConversion.base64StringToByteArray(
              this.bulkKeyBundle.default[1])
      ).then(function(keyBundle) {
        this.bulkKeyBundle.defaultAsKeyBundle = keyBundle;
      }.bind(this));
    } catch(e) {
      return Promise.reject('Deciphered crypto keys, but not JSON');
    }
  }.bind(this), function(err) {
    return Promise.reject(
        'Could not decrypt crypto keys using AES part of stretched kB key');
  });
};

/*
 * setKeys - import kB and crypto/keys
 *
 * @param {String} kB Hex string with kB from FxA onepw protocol
 * @param {Object} cryptoKeys Object with:
 *     - ciphertext {String} A Base64 String containing an AES-CBC ciphertext
 *     - IV {String} A Base64 String containing the AES-CBC Initialization
 *         Vector
 *     - hmac {String} A Hex String containing the HMAC-SHA256 signature
 * @returns {Promise} A promise that will resolve after import of kB and
 *     decryption of cryptoKeys.
 */
FxSyncWebCrypto.prototype.setKeys = function(kB, cryptoKeys) {
  var kBByteArray, cryptoKeysCiphertextByteArray, cryptoKeysIVByteArray,
      cryptoKeysHmacByteArray;

  // Input checking
  try {
    kBByteArray = StringConversion.hexStringToByteArray(kB);
  } catch (e) {
    return Promise.reject('Could not parse kB as a hex string');
  }
  try {
    cryptoKeysCiphertextByteArray = StringConversion.base64StringToByteArray(
        cryptoKeys.ciphertext);
  } catch (e) {
    return Promise.reject(
        'Could not parse cryptoKeys.ciphertext as a base64 string');
  }
  try {
    cryptoKeysIVByteArray =
        StringConversion.base64StringToByteArray(cryptoKeys.IV);
  } catch (e) {
    return Promise.reject('Could not parse cryptoKeys.IV as a base64 string');
  }
  try {
    cryptoKeysHmacByteArray =
        StringConversion.hexStringToByteArray(cryptoKeys.hmac);
  } catch (e) {
    return Promise.reject('Could not parse cryptoKeys.hmac as a hex string');
  }

  return this._importKb(kBByteArray).then(function() {
    // Intentionally using StringConversion.rawStringToByteArray
    // instead of StringConversion.base64StringToByteArray on the ciphertext
    // here - See https://github.com/mozilla/firefox-ios/blob/ \
    // 1cce59c8eac282e151568f1204ffbbcc27349eff/Sync/KeyBundle.swift#L178
    return this._verifySyncKeys(StringConversion.rawStringToByteArray(
        cryptoKeys.ciphertext), cryptoKeysHmacByteArray);
  }.bind(this)).then(function(verified) {
    if (verified) {
      return this._importSyncKeys(cryptoKeysIVByteArray,
          cryptoKeysCiphertextByteArray);
    } else {
      return Promise.reject(
          'SyncKeys hmac could not be verified with current main key');
    }
  }.bind(this));
};

FxSyncWebCrypto.prototype.selectKeyBundle = function() {
  return this.bulkKeyBundle.defaultAsKeyBundle;
};

/*
 * decrypt - verify and decrypt a Weave Basic Object
 *
 * @param {Object} payload Object with:
 *     - ciphertext {String} A Base64 String containing an AES-CBC ciphertext
 *     - IV {String} A Base64 String containing the AES-CBC Initialization
 *         Vector
 *     - hmac {String} A Hex String containing the HMAC-SHA256 signature
 * @param {String} collectionName String The name of the Sync collection
 *     (currently ignored, see
 *     https://github.com/michielbdejong/fxsync-webcrypto/issues/19)
 * @returns {Promise} A promise for the decrypted Weave Basic Object.
 */
FxSyncWebCrypto.prototype.decrypt = function(payload, collectionName) {
  var keyBundle, ciphertextFromRaw, ciphertextFromBase64, ivFromBase64,
      hmacFromHex;
  if (typeof payload !== 'object') {
    return Promise.reject('Payload is not an object');
  }
  if (typeof collectionName !== 'string') {
    return Promise.reject('collectionName is not a string');
  }
  try {
    keyBundle = this.selectKeyBundle(collectionName);
  } catch(e) {
    return Promise.reject('No key bundle found for ' + collectionName +
        ' - did you call setKeys?');
  }
  try {
    ciphertextFromRaw = StringConversion.rawStringToByteArray(
        payload.ciphertext);
    ciphertextFromBase64 = StringConversion.base64StringToByteArray(
        payload.ciphertext);
  } catch(e) {
    return Promise.reject('payload.ciphertext is not a Base64 string');
  }
  try {
    ivFromBase64 = StringConversion.base64StringToByteArray(payload.IV);
  } catch(e) {
    return Promise.reject('payload.IV is not a Base64 string');
  }
  try {
    hmacFromHex = StringConversion.hexStringToByteArray(payload.hmac);
  } catch(e) {
    if (typeof payload.hmac === 'string') {
      return Promise.reject('payload.hmac.length not a multiple of 2');
    } else {
      return Promise.reject('payload.hmac is not a string');
    }
  }
  return crypto.subtle.verify({ name: 'HMAC', hash: 'SHA-256' },
      keyBundle.hmac, hmacFromHex, ciphertextFromRaw).then(function (result) {
    var hasNonHexBytes = function(str) {
      for (var i=0; i<str.length; i++) {
        if (isNaN(parseInt(str[i], 16))) {
          return true;
        }
      }
      return false;
    };

    if (!result) {
      if (hasNonHexBytes(payload.hmac)) {
        return Promise.reject(
            'payload.hmac contains non-hex characters');
      } else {
        return Promise.reject(
            'Record verification failed with current hmac key for ' +
            collectionName);
      }
    }
  }).then(function() {
    return crypto.subtle.decrypt({
          name: 'AES-CBC',
          iv: ivFromBase64,
        }, keyBundle.aes,
        ciphertextFromBase64)
        .then(function (recordArrayBuffer) {
      var recordObj;
      var recordJSON = String.fromCharCode.apply(null,
          new Uint8Array(recordArrayBuffer));
      try {
        recordObj = JSON.parse(recordJSON);
      } catch(e) {
        return Promise.reject('Deciphered record, but not JSON');
      }
      return recordObj;
    }, function(err) {
      return Promise.reject(
          'Could not decrypt record using AES part of key bundle for ' +
          'collection ' + collectionName);
    });
  });
};

FxSyncWebCrypto.prototype._encryptAndSign = function(keyBundle, cleartext) {
  // Generate a random IV using the PRNG of the device
  var IV = new Uint8Array(16);
  exports.crypto.getRandomValues(IV);
  return crypto.subtle.encrypt({
    name: 'AES-CBC',
    iv: IV
  }, keyBundle.aes, cleartext).then(ciphertext => {
    var ciphertextB64 = StringConversion.arrayBufferToBase64String(ciphertext);
    return crypto.subtle.sign({ name: 'HMAC', hash: 'SHA-256' },
                       keyBundle.hmac,
                       StringConversion.rawStringToByteArray(ciphertextB64)
                      ).then(hmac => {
      return {
        hmac: StringConversion.arrayBufferToHexString(hmac),
        ciphertext: ciphertextB64,
        IV: StringConversion.byteArrayToBase64String(IV)
      };
    });
  });
};

/*
 * encrypt - encrypt and sign a record
 *
 * @param {Object} record Object The data to be JSON-stringified and stored
 * @param {String} collectionName String The name of the Sync collection
 *     (currently ignored, see
 *     https://github.com/michielbdejong/fxsync-webcrypto/issues/19)
 * @returns {Promise} A promise for an object with ciphertext, IV, and hmac.
 */
FxSyncWebCrypto.prototype.encrypt = function(record, collectionName) {
  var cleartext, cleartextStr, keyBundle;

  if (typeof record !== 'object') {
    return Promise.reject('Record should be an object');
  }
  if (typeof collectionName !== 'string') {
    return Promise.reject('collectionName is not a string');
  }

  try {
    cleartextStr = JSON.stringify(record);
  } catch(e) {
    return Promise.reject('Record cannot be JSON-stringified');
  }
  cleartext = StringConversion.rawStringToByteArray(cleartextStr);
  try {
    keyBundle = this.selectKeyBundle(collectionName);
  } catch(e) {
    return Promise.reject('No key bundle found for ' + collectionName +
        ' - did you call setKeys?');
  }
  return this._encryptAndSign(keyBundle, cleartext);
};
