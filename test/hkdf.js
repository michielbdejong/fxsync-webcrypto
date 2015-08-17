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
    it('rejects its promise if ikm is wrong');
    it('rejects its promise if info is wrong');
    it('rejects its promise if salt is wrong');
    it('rejects its promise if length is wrong');
  });
});
