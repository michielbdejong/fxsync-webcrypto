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


test('Constructor creates an object with the right methods', function() {
  var fswc = new FxSyncWebCrypto();
  assertEqual(typeof fswc, 'object');
  assertEqual(typeof fswc.setKeys, 'function');
  assertEqual(typeof fswc.verifyAndDecryptRecord, 'function');
});

test('setKeys populates mainSyncKey and defaultDecryptionKey correctly', function() {
  var fixture = window.fxSyncDataExample;
  var fswc = new FxSyncWebCrypto()
  fswc.setKeys(fixture.kB, fixture.syncKeys).then(function() {
    assertEqual(typeof fswc.mainSyncKey, 'object');
    //FIXME: is there a nicer way to check an object's prototype?
    assertEqual(fswc.mainSyncKey.aes.toString(), '[object CryptoKey]');
    assertEqual(fswc.mainSyncKey.hmac.toString(), '[object CryptoKey]');
    assertEqual(typeof fswc.syncKeys, 'object');
    assertEqual(Array.isArray(fswc.syncKeys.default), true);
    assertEqual(typeof fswc.syncKeys.defaultAsKeyBundle, 'object');
    assertEqual(fswc.syncKeys.defaultAsKeyBundle.aes.toString(), '[object CryptoKey]');
    assertEqual(fswc.syncKeys.defaultAsKeyBundle.hmac.toString(), '[object CryptoKey]');
  });
});

test('verifyAndDecryptRecord can verify and decrypt a record', function() {
  var fixture = window.fxSyncDataExample;
  var fswc = new FxSyncWebCrypto()
  fswc.setKeys(fixture.kB, fixture.syncKeys).then(function() {
    return fswc.verifyAndDecryptRecord(fixture.historyEntry.payload, fixture.historyEntry.collectionName);
  }).then(function(decryptedRecord) {
    assertEqual(typeof decryptedRecord, 'object');
  });
});
