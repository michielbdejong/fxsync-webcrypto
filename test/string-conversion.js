/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

describe('utils', function() {
  describe('rawStringToByteArray', function() {
    it('converts a raw string to a ByteArray', function() {
     var ba = window.FxSyncWebCrypto._stringConversion.rawStringToByteArray('hi ✓');
     chai.expect(ba).to.be.instanceOf(Uint8Array);
     chai.expect(ba.length).to.equal(4);
     chai.expect(ba[0]).to.equal(104);
     chai.expect(ba[1]).to.equal(105);
     chai.expect(ba[2]).to.equal(32);
     chai.expect(ba[3]).to.equal(19);
    });
    it('throws an error when input is not a string', function() {
      chai.expect(window.FxSyncWebCrypto._stringConversion.rawStringToByteArray.bind(undefined, 5)).to.throw(Error);
    });
  });
  describe('base64StringToByteArray', function() {
    it('converts a Base64 string to a ByteArray', function() {
     var ba = window.FxSyncWebCrypto._stringConversion.base64StringToByteArray('Af9=');
     chai.expect(ba).to.be.instanceOf(Uint8Array);
     chai.expect(ba.length).to.equal(2);
     chai.expect(ba[0]).to.equal(1);
     chai.expect(ba[1]).to.equal(255);
    });
    it('throws an error when input is not a Base64 string', function() {
      chai.expect(window.FxSyncWebCrypto._stringConversion.base64StringToByteArray.bind(undefined, 'hello')).to.throw(Error);
    });
  });
  describe('hexStringToByteArray', function() {
    it('converts a hex string to a ByteArray', function() {
     var ba = window.FxSyncWebCrypto._stringConversion.hexStringToByteArray('af93');
     chai.expect(ba).to.be.instanceOf(Uint8Array);
     chai.expect(ba.length).to.equal(2);
     chai.expect(ba[0]).to.equal(175);
     chai.expect(ba[1]).to.equal(147);
    });
    it('throws an error when input is not a hex string', function() {
      chai.expect(window.FxSyncWebCrypto._stringConversion.hexStringToByteArray.bind(undefined, 'hello')).to.throw(Error);
    });
  });
  describe('byteArrayToBase64String', function() {
    it('converts a Uint8Array to a Base64', function() {
     var ba = window.FxSyncWebCrypto._stringConversion.hexStringToByteArray('01ff');
     var str = window.FxSyncWebCrypto._stringConversion.byteArrayToBase64String(ba);
     chai.expect(str).to.be.a('string');
     chai.expect(str).to.equal('Af8=');
    });
    it('throws an error when input is not a Uint8Array', function() {
      chai.expect(
           window.FxSyncWebCrypto._stringConversion.byteArrayToBase64String.bind(undefined, new ArrayBuffer(2))).
           to.throw(Error);
    });
  });
  describe('byteArrayToHexString', function() {
    it('converts a Uint8Array to a Base64', function() {
     var ba = window.FxSyncWebCrypto._stringConversion.base64StringToByteArray('Af8=');
     var str = window.FxSyncWebCrypto._stringConversion.byteArrayToHexString(ba);
     chai.expect(str).to.be.a('string');
     chai.expect(str).to.equal('01ff');
    });
    it('throws an error when input is not an Uint8Array', function() {
      chai.expect(
           window.FxSyncWebCrypto._stringConversion.byteArrayToHexString.bind(undefined, new ArrayBuffer(2))).
           to.throw(Error);
    });
  });
  describe('arrayBufferToBase64String', function() {
    it('converts an ArrayBuffer to a Base64', function() {
     var ba = window.FxSyncWebCrypto._stringConversion.hexStringToByteArray('01ff');
     var str = window.FxSyncWebCrypto._stringConversion.arrayBufferToBase64String(ba.buffer);
     chai.expect(str).to.be.a('string');
     chai.expect(str).to.equal('Af8=');
    });
    it('throws an error when input is not an ArrayBuffer', function() {
      chai.expect(
           window.FxSyncWebCrypto._stringConversion.arrayBufferToBase64String.bind(undefined, new Uint8Array(2))).
           to.throw(Error);
    });
  });
  describe('arrayBufferToHexString', function() {
    it('converts an ArrayBuffer to a Base64', function() {
     var ba = window.FxSyncWebCrypto._stringConversion.base64StringToByteArray('Af8=');
     var str = window.FxSyncWebCrypto._stringConversion.arrayBufferToHexString(ba.buffer);
     chai.expect(str).to.be.a('string');
     chai.expect(str).to.equal('01ff');
    });
    it('throws an error when input is not an ArrayBuffer', function() {
      chai.expect(
           window.FxSyncWebCrypto._stringConversion.arrayBufferToHexString.bind(undefined, new Uint8Array(2))).
           to.throw(Error);
    });
  });
});
