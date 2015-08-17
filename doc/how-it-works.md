# How it works
## Where kB and cryptoKeys come from
In previous versions of FxSync, the 'sync key' was generated on the client, and could only
leave the client where it was generated as a slightly modified Base32 string. This library
does not support importing such strings.

In the current version of FxSync, the sync key is stored on the FxAccounts server as 'kB'.
You can retrieve '(kA, kB)' from there using the onepw protocol. The rest of this doc
assumes you already have kB as a Base64 string.

You can get the cryptoKeys by retrieving the crypto/keys record from the FxSync
account for which you are passing kB, and JSON-parsing the result. For instance using [syncclient](https://github.com/mozilla-services/syncclient) like this:

```bash
$ python sync/main.py email@example.com $PASSWORD get_record crypto keys
{u'id': u'keys',
 u'modified': 1439218393.69,
 u'payload': u'{"ciphertext":"PP5yNUYwJJoLcsL5o85i6RZfvanYDrwtChDD/LdKTZ8JOLubZ9DyRv3HMetSkbhL3HLvVm/FJ1Z4F2Z6IKQCxAc5dNnLsBIUUxhOHLbT0x9/jfnqZ8fLtlbkogI3ZlNvbc8iUF1aX+boe0Pv43vM0VvzxrnJDYzZ2a6jm9nbzUn0ldV9sv6vuvGHE6dANnRkZ3wA/q0q8UvjdwpzXBixAw==","IV":"FmosM+XBNy81/9oEAgI4Uw==","hmac":"01a816e4577c6cf3f97b66b4382d0a3e7e9178c75a3d38ed9ac8ad6397c2ecce"}'}
````

## Constructor and setKeys

The constructor does basically nothing. The first interesting crypto stuff comes when you
call setKeys:

````js
var fswc = new FxSyncWebCrypto();
fswc.setKeys(kB, cryptoKeys);
````

The things setKeys does are:
* Convert kB from Base64 to a raw ArrayBuffer.
* Take the HMAC digest of an all-zeroes string using kB as a SHA256 key.
* Import the result as a HMAC-SHA256 key.
* Two rounds of HKDF on an all-zeroes string, with info 'identity.mozilla.com/picl/v1/oldsync'.
* Split the output in two 256-bit strings.
* Use the first one as the AES key and the second one as the HMAC key of the Sync Key Bundle, and store this as this.mainSyncKey.
* Take the ciphertext from there, and construct an ArrayBuffer with the ASCII characters of that Base64 string.
* Use the HMAC key of the Sync Key Bundle to calculate its SHA256 HMAC signature.
* Convert the result to a hex string.
* Check that it matches the HMAC signature of the Sync Key Bundle. Stop if it doesn't.
* Convert the initialization vector (IV in the cryptoKeys) from Base64 to a raw ArrayBuffer.
* Use the AES key of the Sync Key Bundle and the IV to decrypt the ciphertext of the cryptoKeys with AES-CBC (256 bits).
* On success, JSON-parse the cleartext and store it as this.bulkKeyBundle.
* Convert the default keys from Base64 to raw ArrayBuffer, import them as CryptoKey object, and store them on this.bulkKeyBundle.defaultAsKeyBundle (first one is the AES with purpose encrypt/decrypt, second one is the HMAC key with purpose sign/verify).

The bulkKeyBundle look something like this:

````js
{"id":"keys",
 "collection":"crypto",
 "collections":{},
 "default:['dGhlc2UtYXJlLWV4YWN0bHktMzItY2hhcmFjdGVycy4=',
           'eWV0LWFub3RoZXItc2V0LW9mLTMyLWNoYXJhY3RlcnM=']}

````

## decrypt

The decrypt function does the following:

* JSON-parse the payload into an object with ciphertext (base64), IV (base64), and hmac (hex).
* Use this.bulkKeyBundle.defaultAsKeyBundle.HMAC to verify the hmac signature of the ciphertext's Base64 characters.
* Use this.bulkKeyBundle.defaultAsKeyBundle.AES and IV to decrypt the ciphertext.
* JSON-parse the result and return it.

## encrypt

The encrypt function does the following:

* Generate a random initialization vector (IV).
* JSON-stringify the record to form the cleartext.
* Use this.bulkKeyBundle.defaultAsKeyBundle.AES and IV to encrypt the cleartext and obtain the ciphertext.
* Use this.bulkKeyBundle.defaultAsKeyBundle.HMAC to sign the ciphertext's Base64 characters and obtain hmac.
* JSON-stringify an object with ciphertext (Base64), IV (Base64), and hmac (hex) to obtain the payload.
