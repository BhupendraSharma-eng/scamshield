#!/usr/bin/env bash
# Builds ScamShield Guardian APK without Gradle: aapt2 → javac → d8 → zipalign → apksigner.
# Usage: ./build.sh [install]   (install = adb install -r + grant permissions + enable listener)
set -euo pipefail
cd "$(dirname "$0")"

SDK="${ANDROID_HOME:-/opt/homebrew/share/android-commandlinetools}"
API="${API:-36}"
BT="$(ls -d "$SDK"/build-tools/* | sort -V | tail -1)"
JAR="$SDK/platforms/android-$API/android.jar"
JAVA_HOME="${JAVA_HOME:-/opt/homebrew/opt/openjdk@21}"
export PATH="$JAVA_HOME/bin:$PATH"
PKG=in.scamshield.guardian
OUT=build

[ -f "$JAR" ] || { echo "missing $JAR — run: sdkmanager 'platforms;android-$API' 'build-tools;$API.0.0'"; exit 1; }
rm -rf "$OUT" && mkdir -p "$OUT/gen" "$OUT/classes" "$OUT/dex"

echo "▸ resources"
"$BT/aapt2" compile --dir res -o "$OUT/res.zip"
"$BT/aapt2" link -o "$OUT/base.apk" -I "$JAR" --manifest AndroidManifest.xml \
  --java "$OUT/gen" --min-sdk-version 26 --target-sdk-version "$API" "$OUT/res.zip"

echo "▸ java"
javac -source 11 -target 11 -Xlint:-options -encoding UTF-8 -classpath "$JAR" -d "$OUT/classes" \
  $(find src "$OUT/gen" -name '*.java')

echo "▸ dex"
"$BT/d8" --lib "$JAR" --min-api 26 --release --output "$OUT/dex" $(find "$OUT/classes" -name '*.class')

echo "▸ package + sign"
cp "$OUT/base.apk" "$OUT/unsigned.apk"
(cd "$OUT/dex" && zip -q -u ../unsigned.apk classes.dex)
"$BT/zipalign" -f -p 4 "$OUT/unsigned.apk" "$OUT/aligned.apk"
KS=debug.keystore
[ -f "$KS" ] || keytool -genkeypair -keystore "$KS" -storepass android -keypass android -alias scamshield \
  -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=ScamShield Debug" >/dev/null 2>&1
"$BT/apksigner" sign --ks "$KS" --ks-pass pass:android --key-pass pass:android --out ScamShield.apk "$OUT/aligned.apk"
echo "✓ $(pwd)/ScamShield.apk ($(du -h ScamShield.apk | cut -f1))"

if [ "${1:-}" = "install" ]; then
  echo "▸ install"
  adb install -r -g ScamShield.apk
  adb shell pm grant $PKG android.permission.RECEIVE_SMS || true
  adb shell pm grant $PKG android.permission.POST_NOTIFICATIONS || true
  adb shell cmd notification allow_listener $PKG/$PKG.NotificationGuard || true
  adb shell cmd role add-role-holder android.app.role.CALL_SCREENING $PKG 0 || true
  adb shell am start -n $PKG/.MainActivity >/dev/null
  echo "✓ installed and launched"
fi
