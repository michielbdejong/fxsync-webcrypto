describe('hkdf', function() {
  describe('hkdf', function() {
    it('can calculate a hkdf result correctly', function(done) {
      var fixture = window.fxSyncDataExample.hkdf;
      window.FxSyncWebCrypto._keyDerivation.hkdf(fixture.kB, fixture.infoStr, new Uint8Array(64), 64).then(function(bytes) {
        var hex = '';
        for (var i=0; i <bytes.length; ++i) {
          var zeropad = (bytes[i] < 0x10) ? "0" : "";
          hex += zeropad + bytes[i].toString(16);
        }
        chai.expect(hex).to.equal(fixture.outputHex);
        done();
      });
    });
    it('rejects its promise if ikm is wrong', function(done) {
      var fixture = window.fxSyncDataExample.hkdf;
      fixture.kB = 'foo';
      var promise = window.FxSyncWebCrypto._keyDerivation.hkdf(fixture.kB, fixture.infoStr, new Uint8Array(64), 64);
      chai.expect(promise).to.be.rejectedWith(Error).
           and.notify(done);
    });
    it('rejects its promise if info is wrong', function(done) {
      var fixture = window.fxSyncDataExample.hkdf;
      fixture.kB = 'foo';
      var promise = window.FxSyncWebCrypto._keyDerivation.hkdf(fixture.kB, fixture.infoStr, new Uint8Array(64), 64);
      chai.expect(promise).to.be.rejectedWith(Error).
           and.notify(done);
    });
    it('rejects its promise if salt is wrong', function(done) {
      var fixture = window.fxSyncDataExample.hkdf;
      fixture.kB = 'foo';
      var promise = window.FxSyncWebCrypto._keyDerivation.hkdf(fixture.kB, fixture.infoStr, new Uint8Array(64), 64);
      chai.expect(promise).to.be.rejectedWith(Error).
           and.notify(done);
    });
    it('rejects its promise if length is wrong', function(done) {
      var fixture = window.fxSyncDataExample.hkdf;
      var promise = window.FxSyncWebCrypto._keyDerivation.hkdf(fixture.kB, fixture.infoStr, new Uint8Array(64), 32);
      chai.expect(promise).to.be.rejectedWith(Error).
           and.notify(done);
    });
  });
});
