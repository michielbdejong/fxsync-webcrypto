jshint src/ test/
mkdir -p dist/
echo "(function(exports) {" > dist/fxsyncwebcrypto.js
cat src/stringconversion.js src/keyderivation.js src/main.js src/exports.js >> dist/fxsyncwebcrypto.js
echo "})(window);" >> dist/fxsyncwebcrypto.js
