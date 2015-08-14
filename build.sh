echo "(function(window) {" >> dist/fxsync-webcrypto.js
cat src/utils.js src/hkdf.js src/main.js >> dist/fxsync-webcrypto.js
echo "})(window);" >> dist/fxsync-webcrypto.js
