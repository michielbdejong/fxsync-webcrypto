jshint src/ test/
mkdir -p dist/
echo "(function(window) {" > dist/fxsyncwebcrypto.js
cat src/stringconversion.js src/keyderivation.js src/main.js >> dist/fxsyncwebcrypto.js
echo "})(window);" >> dist/fxsyncwebcrypto.js
