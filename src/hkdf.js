/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// hash length is 32 because only SHA256 is used at this moment
var HASH_LENGTH = 32;

var hC = {
  str2bin: null,
  hex2bin: null,
  concatBin: null,
  hkdf: null,
  doHMAC: null,
  bitSlice: null,
  newEmptyArray: null,
  doImportKey: null
};

/**
 * hkdf - The HMAC-based Key Derivation Function
 *
 * @class hkdf
 * @param {bitArray} ikm Initial keying material
 * @param {bitArray} info Key derivation data
 * @param {bitArray} salt Salt
 * @param {integer} length Length of the derived key in bytes
 * @return promise object- It will resolve with `output` data
 */
hC.hkdf = function(ikm, info, salt, length) {

  var numBlocks = Math.ceil(length / HASH_LENGTH);

  function doHKDFRound(roundNumber, prevDigest, prevOutput, hkdfKey) {
    // Do the data accumulating part of an HKDF round. Also, it
    // checks if there are still more rounds left and fires the next
    // Or just finishes the process calling the callback.
    function addToOutput(digest) {
      var output = prevOutput + StringConversion.byteArrayToHexString(digest);

      if (++roundNumber <= numBlocks) {
        return doHKDFRound(roundNumber, digest, output, hkdfKey);
      } else {
        return new Promise(function(resolve, reject) {
          var truncated = hC.bitSlice(StringConversion.hexStringToByteArray(output), 0, length * 8);
          resolve(truncated);
        });
      }
    }
    var input = hC.concatBin(
      hC.concatBin(prevDigest, info),
      hC.str2bin(String.fromCharCode(roundNumber)));
    return hC.doHMAC(input, hkdfKey).then(addToOutput);
  };

  return hC.doImportKey(salt). // Imports the initial key
    then(hC.doHMAC.bind(undefined, ikm)). // Generates the key deriving key
    then(hC.doImportKey). // Imports the key deriving key
    then(doHKDFRound.bind(undefined, 1, hC.newEmptyArray(), ''));
  // Launches the first HKDF round
};

var subtle = window.crypto.subtle;

hC.concatBin = function concatU8Array(buffer1, buffer2) {
  var aux = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
  aux.set(new Uint8Array(buffer1), 0);
  aux.set(new Uint8Array(buffer2), buffer1.byteLength);
  return aux;
};

var tEncoder = new TextEncoder('utf8');
hC.str2bin = tEncoder.encode.bind(tEncoder);

var alg = {
  name: "HMAC",
  hash: "SHA-256"
};
hC.doImportKey = rawKey => subtle.importKey('raw', rawKey, alg,
                                         false, ['sign']);

// Converts a ArrayBuffer into a ArrayBufferView (U8) if it's not that
// already.
var arrayBuffer2Uint8 =
      buff => buff.buffer && buff || new Uint8Array(buff);

hC.doHMAC = (tbsData, hmacKey) =>
  subtle.sign(alg.name, hmacKey, tbsData).then(arrayBuffer2Uint8);

hC.doMAC = (tbhData) =>
  subtle.digest(alg.hash, hC.str2bin(tbhData)).then(arrayBuffer2Uint8);

hC.bitSlice = (arr, start, end) =>
  (end !== undefined ? arr.subarray(start / 8, end / 8) :
                       arr.subarray(start / 8));

hC.newEmptyArray = () => new Uint8Array(0);
