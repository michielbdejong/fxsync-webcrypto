# fxsync-webcrypto
Uses WebCrypto to decrypt data from [Firefox Sync's Global Storage format](http://docs.services.mozilla.com/sync/storageformat5.html).

## Usage
You will need three things:

* [WebCrypto](http://www.w3.org/TR/WebCryptoAPI/)
* A client for Firefox Accounts (for instance gaia's [FxAccountsClients](https://github.com/mozilla-b2g/gaia/blob/master/apps/system/js/fx_accounts_manager.js))
* A client for Firefox Sync (for instance [kinto.js]() + [syncto](), [straight XHR](http://mxr.mozilla.org/mozilla-central/source/services/sync/tests/unit/test_httpd_sync_server.js), or [a python-based one](https://github.com/mozilla-services/syncclient))

The steps are as follows:

### Get the kB key from FxA

Use the [onepw protocol](https://github.com/mozilla/fxa-auth-server/wiki/onepw-protocol)) to retrieve a pair of encryption keys (`kA` and `kB`) from the FxA service. Your FxAccountsClient is hopefully able to do this for you. Discard `kA` and hold on to `kB` (it should be a hex string of 64 characters).

### Check the storage format

This library currently only supports [storage format 5](http://docs.services.mozilla.com/sync/storageformat5.html), so first retrieve the [metaglobal record](http://docs.services.mozilla.com/sync/storageformat5.html#metaglobal-record) to make sure that the rest of the data on the FxSync account is in the right format. Example using mozilla-services's syncclient:

```bash
$ python sync/main.py alexis@notmyidea.org $PASSWORD get_record meta global
{u'id': u'global',
 u'modified': 1437655930.34,
 u'payload': u'{"syncID":"35sY_luKUnYO","storageVersion":5,"declined":["prefs","bookmarks","addons"],"engines":{"clients":{"version":1,"syncID":"VWMk-0KZ8aKh"},"tabs":{"version":1,"syncID":"eGExUapwMq0O"},"forms":{"version":1,"syncID":"Tgd0wt_q7nQO"},"history":{"version":1,"syncID":"vAIUDLBox_g4"},"passwords":{"version":1,"syncID":"vNno7ecPn7P2"}}}'}
````

In this example we're good, because the value of `storageVersion` there is 5.

### Retrieve the CryptoKeys object.

Similar to how you just retrieved `meta/global`, retrieve `crypto/keys`:

```bash
$ python sync/main.py alexis@notmyidea.org $PASSWORD get_record crypto keys
{u'id': u'keys',
 u'modified': 1439218393.69,
 u'payload': u'{"ciphertext":"PP5yNUYwJJoLcsL5o85i6RZfvanYDrwtChDD/LdKTZ8JOLubZ9DyRv3HMetSkbhL3HLvVm/FJ1Z4F2Z6IKQCxAc5dNnLsBIUUxhOHLbT0x9/jfnqZ8fLtlbkogI3ZlNvbc8iUF1aX+boe0Pv43vM0VvzxrnJDYzZ2a6jm9nbzUn0ldV9sv6vuvGHE6dANnRkZ3wA/q0q8UvjdwpzXBixAw==","IV":"FmosM+XBNy81/9oEAgI4Uw==","hmac":"01a816e4577c6cf3f97b66b4382d0a3e7e9178c75a3d38ed9ac8ad6397c2ecce"}'}
````

Note that the payload is a JSON-encoded object, in which ciphertext and IV are base64 strings, and hmac is a hex string.

### Construct the FxSyncWebCrypto object

Using `kB` and `cryptoKeys`, you can call the FxSyncWebCrypto constructor:

````js
var kB = '85c4f8c1d8e3e2186824c127af786891dd03c6e05b1b45f28f7181211bf2affb';
var syncKeys = {
  ciphertext: 'PP5yNUYwJJoLcsL5o85i6RZfvanYDrwtChDD/LdKTZ8JOLubZ9DyRv3HMetSkbhL3HLvVm/FJ1Z4F2Z6IKQCxAc5dNnLsBIUUxhOHLbT0x9/jfnqZ8fLtlbkogI3ZlNvbc8iUF1aX+boe0Pv43vM0VvzxrnJDYzZ2a6jm9nbzUn0ldV9sv6vuvGHE6dANnRkZ3wA/q0q8UvjdwpzXBixAw==',
  IV: 'FmosM+XBNy81/9oEAgI4Uw==',
  hmac: '01a816e4577c6cf3f97b66b4382d0a3e7e9178c75a3d38ed9ac8ad6397c2ecce'
};
var historyEntry = {
  payload: '{"ciphertext":"o/VpkqMj1tlT8t2youwsS2FgvQeonoHxqjGsRTu1+4swfyBq/QsnKfgOOMmDIXZiPC3hOCNUlf/NtQiEe55hzJZEKLBshaLfXotai6KrprwrmykfiXnwn73n+nYNs8BXL5awDHoaJToyFgF4PYokl7mwN7YC2xFiPgwO7Z2u/8r5RfnPV9MoafqvlvUkW+Tqs+QHeHS/iuSA0P2h/j5ynt9v4xDWLVfEMce0KOKHQ5Qj7BmEPAieWP1trkkDmTdVi2euWrs+fuG4C6PgY4A2j2DbNLVIloqpDVkqM2fgh0YOM9L2NC/uiKEb1Ynr2Fos","IV":"kXL3hb11ltD+Jl0YFk+PlQ==","hmac":"cb727efe7a3f0307921cecbd1a97c03f06a4d75c42026089494d84fcf92dbff9"}',
  collectionName: 'history'
};

var fswc = new FxSyncWebCrypto();
fswc.setKeys(kB, syncKeys).then(function() {
}).then(function() {
  return fswc.verifyAndDecryptRecord(historyEntry.payload, historyEntry.collectionName);
}).then(function(recordObj) {
  console.log('Decrypted history entry', recordObj);
  // Should print this to the console:
  // Decrypted history entry Object { id: "_9sCUbahs0ay", histUri: "https://developer.mozilla.org/en-US…", title: "Object.prototype.__proto__ - JavaSc…", visits: Array[1] }

  return fswc.signAndEncryptRecord({foo: 'bar'}, 'my collection');
}).then(function(payload) {
  return fswc.verifyAndDecryptRecord(payload, 'my collection');
}).then(function(record) {
  console.log('decrypted record', record);
  // Should print this to the console:
  // decrypted record Object { foo: "bar" }
}, function(err) {
  console.log('error', err);
});
````

Note how you always have to specify the collection name (e.g. 'history' or 'passwords'), so that FxSyncWebCrypto can make sure it uses the right collection key bundle. This is because the CryptoKeys object potentially contains a different key bundle for each collection.

## Functions provided
### constructor FxSyncWebCrypto
Arguments: none

### setKeys(kB, syncKeys)
TODO: hmac verification of syncKeys is not working yet
This function is where all the exciting stuff happens. First, kB is stretched using 64-bit HKDF over the string 'identity.mozilla.com/picl/v1/oldsync'. The result is split in two, where the first half becomes the AES key for decrypting cryptoKeysCiphertext (with initialization vector cryptoKeysIV), and the second half becomes the HMAC key for verifying the cryptoKeysHmac signature.

Arguments:
* kB - A 64-byte hex string representing the 1024-bit `kB` key described in [onepw](https://github.com/mozilla/fxa-auth-server/wiki/onepw-protocol)
* syncKeys - an object, containing:
  * ciphertext - A Base64 string representing the ciphertext of the [CryptoKeys record](http://docs.services.mozilla.com/sync/storageformat5.html#crypto-keys-record) for the FxSync account.
  * IV - A Base64 string representing the initialization vector for the [CryptoKeys record](http://docs.services.mozilla.com/sync/storageformat5.html#crypto-keys-record) for the FxSync account.
  * hmac - a 64-byte hex string representing the 1024-bit hmac signature for the [CryptoKeys record](http://docs.services.mozilla.com/sync/storageformat5.html#crypto-keys-record) for the FxSync account.
Returns a promise that resolves when initialization was successful, and rejects if the CryptoKeys could not be decrypted with the stretched kB, or if WebCrypto is not available.

### signAndEncryptRecord
TODO: implement
Arguments:
* record: The object to JSON-stringify, sign, and encrypt
* collectionName: The name of the FxSync collection for which to encrypt (see http://docs.services.mozilla.com/sync/storageformat5.html#encryption).
Returns:
A promise for a JSON string encoding an object with fields ciphertext, IV, and hmac, which is the payload to be uploaded to the FxSync server.

### verifyAndDecryptRecord
TODO: hmac verification is not working yet
This function JSON-parses the payload, checks the HMAC signature, and if that matches, uses AES-CBC to decrypt the ciphertext, given the IV.

Arguments:
* payload: A JSON string encoding an object with fields ciphertext, IV, and hmac, presumably the payload of a download from the FxSync server.
* collectionName: The name of the FxSync collection for which to decrypt (see http://docs.services.mozilla.com/sync/storageformat5.html#decryption).
Returns:
A promise for an object (the record again that was originally JSON-stringified and encrypted on this or on another FxSync client).

