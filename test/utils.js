function assertEqual(a, b) {
  return expect(a).to.equal(b);
}

describe('utils', function() {
  describe('rawStringToByteArray', function() {
    it('converts a raw string to a ByteArray');
    it('throws an error when input is not a string');
  });
  describe('base64StringToByteArray', function() {
    it('converts a Base64 string to a ByteArray');
    it('throws an error when input is not a Base64 string');
  });
  describe('hexStringToByteArray', function() {
    it('converts a hex string to a ByteArray');
    it('throws an error when input is not a hex string');
  });
  describe('arrayBufferToBase64String', function() {
    it('converts an ArrayBuffer to a Base64 string');
    it('throws an error when input is not an ArrayBuffer');
  });
  describe('arrayBufferToHexString', function() {
    it('converts an ArrayBuffer to a hex string');
    it('throws an error when input is not an ArrayBuffer');
  });
});
