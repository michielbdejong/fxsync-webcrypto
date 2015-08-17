describe('FxSyncWebCrypto', function() {
  describe('constructor', function() {
    it('creates an object with the right methods', function() {
      var fswc = new FxSyncWebCrypto();
      chai.expect(fswc).to.be.an('object');
      chai.expect(fswc.setKeys).to.be.a('function');
      chai.expect(fswc.decrypt).to.be.a('function');
      chai.expect(fswc.encrypt).to.be.a('function');
    });
  });

  describe('setKeys', function() {
    it('populates mainSyncKey and defaultDecryptionKey correctly', function() {
      var fixture = window.fxSyncDataExample;
      var fswc = new FxSyncWebCrypto()
      fswc.setKeys(fixture.kB, fixture.syncKeys).then(function() {
        chai.expect(fswc.mainSyncKey).to.be.an('object');
        chai.expect(fswc.mainSyncKey.aes).to.be.instanceof(CryptoKey);
        chai.expect(fswc.mainSyncKey.hmac).to.be.instanceof(CryptoKey);
        chai.expect(fswc.bulkKeyBundle).to.be.an('object');
        chai.expect(fswc.bulkKeyBundle.default).to.be.instanceof(Array);
        chai.expect(fswc.bulkKeyBundle.defaultAsKeyBundle).to.be.an('object');
        chai.expect(fswc.bulkKeyBundle.defaultAsKeyBundle.aes).to.be.instanceof(CryptoKey);
        chai.expect(fswc.bulkKeyBundle.defaultAsKeyBundle.hmac).to.be.instanceof(CryptoKey);
      });
    });

    it('rejects promise if syncKeys hmac is wrong', function() {
      var fixture = window.fxSyncDataExample;
      var fswc = new FxSyncWebCrypto();
      var syncKeysWrong = JSON.parse(JSON.stringify(fixture.syncKeys));
      syncKeysWrong.hmac = 'deadbeef';
      fswc.setKeys(fixture.kB, syncKeysWrong).then(function() {
        chai.expect(false).to.equal(true);
      }, function(err) {
        chai.expect(err).to.equal('SyncKeys hmac could not be verified with current main key');
      });
    });
    it('rejects promise if syncKeys ciphertext is wrong');
    it('rejects promise if syncKeys IV is wrong');
  });

  describe('decrypt', function() {
    it('can verify and decrypt a record', function() {
      var fixture = window.fxSyncDataExample;
      var fswc = new FxSyncWebCrypto();
      fswc.setKeys(fixture.kB, fixture.syncKeys).then(function() {
        return fswc.decrypt(fixture.historyEntryEnc.payload, fixture.historyEntryEnc.collectionName);
      }).then(function(decryptedRecord) {
        chai.expect(decryptedRecord).to.be.an('object');
        chai.expect(decryptedRecord.id).to.equal(fixture.historyEntryDec.payload.id);
        chai.expect(decryptedRecord.histUri).to.equal(fixture.historyEntryDec.payload.histUri);
        chai.expect(decryptedRecord.title).to.equal(fixture.historyEntryDec.payload.title);
        chai.expect(decryptedRecord.visits).to.be.instanceof(Array);
        chai.expect(decryptedRecord.visits.length).to.equal(1);
        chai.expect(decryptedRecord.visits[0].date).to.equal(fixture.historyEntryDec.payload.visits[0].date);
        chai.expect(decryptedRecord.visits[0].type).to.equal(fixture.historyEntryDec.payload.visits[0].type);
      });
    });

    it('rejects promise if collectionName is not a string', function() {
      var fixture = window.fxSyncDataExample;
      var fswc = new FxSyncWebCrypto();
      var promise = fswc.setKeys(fixture.kB, fixture.syncKeys).then(function() {
        return fswc.decrypt(fixture.historyEntryEnc.payload, 5);
      });
      chai.expect(promise).to.be.rejectedWith('collectionName is not a string');
    });

    it('rejects promise if record is not a string', function() {
      var fixture = window.fxSyncDataExample;
      var fswc = new FxSyncWebCrypto();
      var promise = fswc.setKeys(fixture.kB, fixture.syncKeys).then(function() {
        return fswc.decrypt(5, fixture.historyEntryEnc.collectionName);
      });
      chai.expect(promise).to.be.rejectedWith('Payload is not a string');
    });

    it('rejects promise if record is not a JSON string', function() {
      var fixture = window.fxSyncDataExample;
      var fswc = new FxSyncWebCrypto();
      var promise = fswc.setKeys(fixture.kB, fixture.syncKeys).then(function() {
        return fswc.decrypt('boo', fixture.historyEntryEnc.collectionName);
      });
      chai.expect(promise).to.be.rejectedWith('Payload is not a JSON string');
    });

    it('rejects promise if record hmac is wrong', function() {
      var fixture = window.fxSyncDataExample;
      var fswc = new FxSyncWebCrypto();
      var promise = fswc.setKeys(fixture.kB, fixture.syncKeys).then(function() {
        var payloadObj = JSON.parse(fixture.historyEntryEnc.payload);
        payloadObj.hmac = 'deadbeef';
        return fswc.decrypt(JSON.stringify(payloadObj), fixture.historyEntryEnc.collectionName);
      });
      chai.expect(promise).to.be.rejectedWith('Record verification failed with current hmac key for history');
    });

    it('rejects promise if record ciphertext is wrong');
    it('rejects promise if record IV is wrong');
  });

  describe('encrypt', function() {
    it('can sign and encrypt a record', function() {
      var fixture = window.fxSyncDataExample;
      var fswc = new FxSyncWebCrypto();
      fswc.setKeys(fixture.kB, fixture.syncKeys).then(function() {
        return fswc.encrypt(fixture.historyEntryDec.payload, fixture.historyEntryDec.collectionName);
      }).then(function(encryptedRecord) {
        //see if we can decrypt it again
        return fswc.decrypt(encryptedRecord, fixture.historyEntryDec.collectionName);
      }).then(function(redecryptedRecord) {
        chai.expect(redecryptedRecord).to.deep.equal(fixture.historyEntryDec.payload);
      });
    });

    it('rejects promise if record is not an object', function() {
      var fixture = window.fxSyncDataExample;
      var fswc = new FxSyncWebCrypto();
      var promise = fswc.setKeys(fixture.kB, fixture.syncKeys).then(function() {
        return fswc.encrypt('boo', fixture.historyEntryDec.collectionName);
      });
      chai.expect(promise).to.be.rejectedWith('Record should be an object');
    });

    it('rejects promise if record cannot be JSON-stringified', function() {
      var fixture = window.fxSyncDataExample;
      var fswc = new FxSyncWebCrypto();
      var promise = fswc.setKeys(fixture.kB, fixture.syncKeys).then(function() {
        var myObject = {};
        myObject.cyclicReference = myObject;
        return fswc.encrypt(myObject, fixture.historyEntryDec.collectionName);
      });
      chai.expect(promise).to.be.rejectedWith('Record cannot be JSON-stringified');
    });

    it('rejects promise if collectionName is not a string', function() {
      var fixture = window.fxSyncDataExample;
      var fswc = new FxSyncWebCrypto();
      var promise = fswc.setKeys(fixture.kB, fixture.syncKeys).then(function() {
        return fswc.encrypt(fixture.historyEntryDec.payload, 5);
      });
      chai.expect(promise).to.be.rejectedWith('collectionName is not a string');
    });
  });
});
