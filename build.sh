#!/usr/bin/env bash
# Builds Grove Guard without Gradle, using only open tools:
#   aapt2 (resources), javac (Java 8 bytecode), dx (dex), uber-apk-signer (signing).
# libs/bc-from-hypatia.jar holds the Bouncy Castle (MIT) classes Hypatia 3.18 shipped, used for signature checks.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
TOOLS="${TOOLS:-$ROOT/../tools}"
ANDROID_JAR="${ANDROID_JAR:-$TOOLS/ap/android-34/android.jar}"
AAPT2="${AAPT2:-$TOOLS/prebuilt/linux/aapt2_64}"
DX_JAR="${DX_JAR:-$(ls "$TOOLS"/d2j/*/lib/dx-*.jar 2>/dev/null | head -1)}"
SIGNER="${SIGNER:-$TOOLS/uber.jar}"
KEYSTORE="${KEYSTORE:-$ROOT/release.keystore}"
VERSION_CODE="${VERSION_CODE:-1}"
VERSION_NAME="${VERSION_NAME:-1.0.0}"
LIBS="$ROOT/libs/bc-from-hypatia.jar"

SRC="$ROOT/app/src/main"
OUT="$ROOT/build"
rm -rf "$OUT"
mkdir -p "$OUT/gen" "$OUT/classes" "$OUT/signed"

sed 's#<manifest xmlns:android="http://schemas.android.com/apk/res/android">#<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.grove.guard">#' \
  "$SRC/AndroidManifest.xml" > "$OUT/AndroidManifest.xml"

echo "> aapt2 compile"
"$AAPT2" compile --dir "$SRC/res" -o "$OUT/res.zip"
echo "> aapt2 link"
"$AAPT2" link -I "$ANDROID_JAR" --manifest "$OUT/AndroidManifest.xml" --java "$OUT/gen" -A "$SRC/assets" \
  --min-sdk-version 26 --target-sdk-version 34 \
  --version-code "$VERSION_CODE" --version-name "$VERSION_NAME" \
  -o "$OUT/unsigned.apk" "$OUT/res.zip"

echo "> javac"
find "$SRC/java" "$OUT/gen" -name '*.java' > "$OUT/sources.txt"
javac -nowarn -source 8 -target 8 -encoding UTF-8 -Xlint:-options \
  -bootclasspath "$ANDROID_JAR" -classpath "$ANDROID_JAR:$LIBS" -d "$OUT/classes" @"$OUT/sources.txt"

echo "> dx"
java -cp "$DX_JAR" com.android.dx.command.Main --dex --min-sdk-version=26 --output="$OUT/classes.dex" "$OUT/classes" "$LIBS"
(cd "$OUT" && zip -qj unsigned.apk classes.dex)

echo "> sign"
if [ ! -f "$KEYSTORE" ]; then
  keytool -genkeypair -keystore "$KEYSTORE" -storepass guard-local -keypass guard-local -alias guard \
    -keyalg RSA -keysize 3072 -validity 10000 -dname "CN=Grove Guard, O=Grove, C=MY" >/dev/null 2>&1
fi
java -jar "$SIGNER" -a "$OUT/unsigned.apk" -o "$OUT/signed" --ks "$KEYSTORE" --ksAlias guard \
  --ksPass guard-local --ksKeyPass guard-local --allowResign >/dev/null
cp "$OUT"/signed/*.apk "$OUT/GroveGuard-$VERSION_NAME.apk"
echo "Built $OUT/GroveGuard-$VERSION_NAME.apk"
