// FxSyncWebCrypto is a separate repo now, but it's likely we want
// to include it in the main gaia repo, so its tests are run there.
// I'm running tests from the browser console for now, will port to
// appropriate test framework once I get up and running with running
// gaia tests and we have the skeleton for the synchronizer app.

function assertEqual(a, b) {
  if (a === b) {
    console.log('assertion OK', a, b);
  } else {
    console.log('assertion failed', a, b);
  }
}
function test(testName, runTest) {
  console.log('RUNNING TEST: ' + testName);
  runTest();
}

var tests = [
  /* 0 */
  function() {
    test('Constructor creates an object with the right methods', function() {
      var fswc = new FxSyncWebCrypto();
      assertEqual(typeof fswc, 'object');
      assertEqual(typeof fswc.setKeys, 'function');
      assertEqual(typeof fswc.decrypt, 'function');
    });
  },

  /* 1 */
  function() {
    test('setKeys populates mainSyncKey and defaultDecryptionKey correctly', function() {
      var fixture = window.fxSyncDataExample;
      var fswc = new FxSyncWebCrypto()
      fswc.setKeys(fixture.kB, fixture.syncKeys).then(function() {
        assertEqual(typeof fswc.mainSyncKey, 'object');
        assertEqual(fswc.mainSyncKey.aes instanceof CryptoKey, true);
        assertEqual(fswc.mainSyncKey.hmac instanceof CryptoKey, true);
        assertEqual(typeof fswc.syncKeys, 'object');
        assertEqual(Array.isArray(fswc.syncKeys.default), true);
        assertEqual(typeof fswc.syncKeys.defaultAsKeyBundle, 'object');
        assertEqual(fswc.syncKeys.defaultAsKeyBundle instanceof CryptoKey, true);
        assertEqual(fswc.syncKeys.defaultAsKeyBundle.hmac instanceof CryptoKey, true);
      });
    });
  },

  /* 2 */
  function() {
    test('decrypt can verify and decrypt a record', function() {
      var fixture = window.fxSyncDataExample;
      var fswc = new FxSyncWebCrypto();
      fswc.setKeys(fixture.kB, fixture.syncKeys).then(function() {
        return fswc.decrypt(fixture.historyEntryEnc.payload, fixture.historyEntryEnc.collectionName);
      }).then(function(decryptedRecord) {
        assertEqual(typeof decryptedRecord, 'object');
        assertEqual(decryptedRecord.id, fixture.historyEntryDec.payload.id);
        assertEqual(decryptedRecord.histUri, fixture.historyEntryDec.payload.histUri);
        assertEqual(decryptedRecord.title, fixture.historyEntryDec.payload.title);
        assertEqual(Array.isArray(decryptedRecord.visits), true);
        assertEqual(decryptedRecord.visits.length, 1);
        assertEqual(decryptedRecord.visits[0].date, fixture.historyEntryDec.payload.visits[0].date);
        assertEqual(decryptedRecord.visits[0].type, fixture.historyEntryDec.payload.visits[0].type);
      });
    });
  },

  /* 3 */
  function() {
    test('encrypt can sign and encrypt a record', function() {
      var fixture = window.fxSyncDataExample;
      var fswc = new FxSyncWebCrypto();
      fswc.setKeys(fixture.kB, fixture.syncKeys).then(function() {
        return fswc.encrypt(fixture.historyEntryDec.payload, fixture.historyEntryDec.collectionName);
      }).then(function(encryptedRecord) {
        assertEqual(encryptedRecord, fixture.historyEntryEnc.payload);
      });
    });
  },

  /* 4 */
  function() {
    test('encrypt rejects promise if record is not an object', function() {
      var fixture = window.fxSyncDataExample;
      var fswc = new FxSyncWebCrypto();
      fswc.setKeys(fixture.kB, fixture.syncKeys).then(function() {
        return fswc.encrypt('boo', fixture.historyEntryDec.collectionName);
      }).then(function() {
        assertEqual(false, true);
      }, function(err) {
        assertEqual(err, 'Record should be an object');
      });
    });
  },

  /* 5 */
  function() {
    test('encrypt rejects promise if record cannot be JSON-stringified', function() {
      var fixture = window.fxSyncDataExample;
      var fswc = new FxSyncWebCrypto();
      fswc.setKeys(fixture.kB, fixture.syncKeys).then(function() {
        var myObject = {};
        myObject.cyclicReference = myObject;
        return fswc.encrypt(myObject, fixture.historyEntryDec.collectionName);
      }).then(function() {
        assertEqual(false, true);
      }, function(err) {
        assertEqual(err, 'Record cannot be JSON-stringified');
      });
    });
  },

  /* 6 */
  function() {
    test('encrypt rejects promise if collectionName is not a string', function() {
      var fixture = window.fxSyncDataExample;
      var fswc = new FxSyncWebCrypto();
      fswc.setKeys(fixture.kB, fixture.syncKeys).then(function() {
        return fswc.encrypt(fixture.historyEntryDec.payload, 5);
      }).then(function() {
        assertEqual(false, true);
      }, function(err) {
        assertEqual(err, 'collectionName is not a string');
      });
    });
  },

  /* 7 */
  function() {
    test('decrypt rejects promise if collectionName is not a string', function() {
      var fixture = window.fxSyncDataExample;
      var fswc = new FxSyncWebCrypto();
      fswc.setKeys(fixture.kB, fixture.syncKeys).then(function() {
        return fswc.decrypt(fixture.historyEntryEnc.payload, 5);
      }).then(function() {
        assertEqual(false, true);
      }, function(err) {
        assertEqual(err, 'collectionName is not a string');
      });
    });
  },

  /* 8 */
  function() {
    test('decrypt rejects promise if record is not a string', function() {
      var fixture = window.fxSyncDataExample;
      var fswc = new FxSyncWebCrypto();
      fswc.setKeys(fixture.kB, fixture.syncKeys).then(function() {
        return fswc.decrypt(5, fixture.historyEntryEnc.collectionName);
      }).then(function() {
        assertEqual(false, true);
      }, function(err) {
        assertEqual(err, 'Payload is not a string');
      });
    });
  },

  /* 9 */
  function() {
    test('decrypt rejects promise if record is not a JSON string', function() {
      var fixture = window.fxSyncDataExample;
      var fswc = new FxSyncWebCrypto();
      fswc.setKeys(fixture.kB, fixture.syncKeys).then(function() {
        return fswc.decrypt('boo', fixture.historyEntryEnc.collectionName);
      }).then(function() {
        assertEqual(false, true);
      }, function(err) {
        assertEqual(err, 'Payload is not a JSON string');
      });
    });
  },

  /* 10 */
  function() {
    test('decrypt rejects promise if record hmac is wrong', function() {
      var fixture = window.fxSyncDataExample;
      var fswc = new FxSyncWebCrypto();
      fswc.setKeys(fixture.kB, fixture.syncKeys).then(function() {
        var payloadObj = JSON.parse(fixture.historyEntryEnc.payload);
        payloadObj.hmac = 'deadbeef';
        return fswc.decrypt(JSON.stringify(payloadObj), fixture.historyEntryEnc.collectionName);
      }).then(function() {
        assertEqual(false, true);
      }, function(err) {
        assertEqual(err, 'Record verification failed with current hmac key for history');
      });
    });
  },

  /* 11 */
  function() {
    test('setKeys rejects promise if syncKeys hmac is wrong', function() {
      var fixture = window.fxSyncDataExample;
      var fswc = new FxSyncWebCrypto();
      var syncKeysWrong = JSON.parse(JSON.stringify(fixture.syncKeys));
      syncKeysWrong.hmac = 'deadbeef';
      fswc.setKeys(fixture.kB, syncKeysWrong).then(function() {
        assertEqual(false, true);
      }, function(err) {
        assertEqual(err, 'SyncKeys hmac could not be verified with current main key');
      });
    });
  }
];

//...
window.tests = tests;
