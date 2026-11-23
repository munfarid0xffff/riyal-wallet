#!/usr/bin/env bash
# Builds RiyalCoin-Wallet.apk on your own machine (Linux / macOS). Run from the wallet/ folder:  ./build-android.sh
set -euo pipefail
cd "$(dirname "$0")"

need() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: '$1' not found. $2"; exit 1; }; }
need node  "Install Node 20+ from https://nodejs.org"
need npm   "Install Node 20+ from https://nodejs.org"
need cargo "Install Rust from https://rustup.rs"
need rustup "Install Rust from https://rustup.rs"
need java  "Install JDK 17 (e.g. Temurin 17)"
need keytool "Install JDK 17"

# Android SDK: set ANDROID_HOME, or use Android Studio's default location
if [ -z "${ANDROID_HOME:-}" ]; then
  for d in "$HOME/Android/Sdk" "$HOME/Library/Android/sdk"; do [ -d "$d" ] && ANDROID_HOME="$d"; done
fi
[ -n "${ANDROID_HOME:-}" ] && [ -d "$ANDROID_HOME" ] || { echo "ERROR: Android SDK not found. Install Android Studio, or set ANDROID_HOME."; exit 1; }
export ANDROID_HOME ANDROID_SDK_ROOT="$ANDROID_HOME"

SDKM="$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager"
[ -x "$SDKM" ] || { echo "ERROR: Android cmdline-tools missing. In Android Studio: SDK Manager > SDK Tools > 'Android SDK Command-line Tools'."; exit 1; }
yes | "$SDKM" --licenses >/dev/null 2>&1 || true
"$SDKM" "platforms;android-34" "build-tools;34.0.0" "ndk;26.1.10909125"
export NDK_HOME="$ANDROID_HOME/ndk/26.1.10909125"

rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android

npm install
npm run icons
[ -d src-tauri/gen/android ] || npm run tauri -- android init
npm run tauri -- android build --apk

BT="$ANDROID_HOME/build-tools/34.0.0"
APK=$(find src-tauri/gen/android -name "*-release-unsigned.apk" | head -n1)
[ -n "$APK" ] || { echo "ERROR: unsigned APK not found"; exit 1; }

# Signing key: created once and kept (keep this file + password safe: updates must use the same key)
KS="$HOME/.riyalcoin-wallet-release.jks"
if [ ! -f "$KS" ]; then
  echo "Creating your signing key at $KS"
  read -r -s -p "Choose a keystore password (min 6 chars): " PASS; echo
  keytool -genkeypair -keystore "$KS" -alias riyalcoin -keyalg RSA -keysize 2048 -validity 10000 \
    -storepass "$PASS" -keypass "$PASS" -dname "CN=RiyalCoin Wallet"
else
  read -r -s -p "Keystore password: " PASS; echo
fi

"$BT/zipalign" -f -p 4 "$APK" aligned.apk
"$BT/apksigner" sign --ks "$KS" --ks-key-alias riyalcoin --ks-pass "pass:$PASS" --out RiyalCoin-Wallet.apk aligned.apk
rm -f aligned.apk
"$BT/apksigner" verify RiyalCoin-Wallet.apk
echo
echo "DONE: $(pwd)/RiyalCoin-Wallet.apk  -- copy it to your phone and install (allow 'install unknown apps')."
