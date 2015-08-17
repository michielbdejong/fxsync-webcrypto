jshint src/ test/
mkdir -p dist/
echo "(function(window) {" > dist/fxsync-webcrypto.js
cat src/string-conversion.js src/key-derivation.js src/main.js >> dist/fxsync-webcrypto.js
echo "})(window);" >> dist/fxsync-webcrypto.js
