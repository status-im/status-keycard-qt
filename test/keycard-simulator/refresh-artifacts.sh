#!/usr/bin/env bash
#
# Regenerates one applet version's vendored artifacts from a status-keycard checkout.
# Run this only when bumping the applet or jcardsim; the produced jars are committed so that running
# the simulator needs ONLY a JVM (no status-keycard checkout, JavaCard SDK, or Gradle).
#
# STATUS_KEYCARD_DIR is REQUIRED (no default — these jars are committed and shared by everyone).
# The checkout must be at the version's SHA (see versions/<version>/version.properties). The applet is
# compiled from source below (javac --release), so you do NOT need `./gradlew compileJava` — which
# fails on JDK 9+ anyway because status-keycard targets source/target 1.6. You only need the prebuilt
# jcardsim + keycard-math jars present in the checkout (and, for 4.0, the SDK + bcprov in the Gradle
# cache, produced by building status-keycard's SDK module).
#
# Usage:
#     STATUS_KEYCARD_DIR=/path/to/status-keycard ./refresh-artifacts.sh <version>     # e.g. 3.2

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

VERSION="${1:-}"
[ -n "$VERSION" ] || { echo "Usage: STATUS_KEYCARD_DIR=/path/to/status-keycard $0 <version>   (e.g. 3.2)"; exit 1; }

VDIR="$HERE/versions/$VERSION"
PROPS="$VDIR/version.properties"
[ -f "$PROPS" ] || { echo "ERROR: unknown version '$VERSION' (no $PROPS)"; exit 1; }

if [ -z "${STATUS_KEYCARD_DIR:-}" ]; then
    echo "ERROR: STATUS_KEYCARD_DIR is not set. Point it at a built status-keycard checkout, e.g.:"
    echo "         STATUS_KEYCARD_DIR=/path/to/status-keycard $0 $VERSION"
    exit 1
fi
SK="$STATUS_KEYCARD_DIR"
[ -d "$SK/.git" ] || { echo "ERROR: STATUS_KEYCARD_DIR=$SK is not a git checkout of status-keycard"; exit 1; }

getprop() { sed -n "s/^$1=//p" "$PROPS"; }
needsPersonalization="$(getprop needsPersonalization)"

jcardsim="$SK/jcardsim/jcardsim-3.0.5-SNAPSHOT.jar"
math="$SK/keycard-math/keycard-math.jar"
appletSrc="$SK/src/main/java/im/status/keycard"
[ -f "$jcardsim" ]  || { echo "ERROR: missing $jcardsim"; exit 1; }
[ -f "$math" ]      || { echo "ERROR: missing $math"; exit 1; }
[ -d "$appletSrc" ] || { echo "ERROR: missing applet source $appletSrc (checkout status-keycard)"; exit 1; }

mkdir -p "$HERE/libs/common" "$VDIR/libs"
cp "$jcardsim" "$HERE/libs/common/jcardsim-3.0.5-SNAPSHOT.jar"   # version-independent (shared)
cp "$math"     "$VDIR/libs/keycard-math.jar"

# Compile the applet at a portable bytecode level instead of packaging status-keycard's gradle output
# (build/classes/java/main). The applet is the highest-versioned class on the simulator classpath, so
# if it's built with a newer JDK (e.g. 17 -> class 61) it forces that JRE at runtime — which breaks a
# double-clicked macOS app whose JRE (resolved via /usr/bin/java, not your terminal's PATH) may be
# older. JavaCard source is Java 8-level, so 11 compiles cleanly and runs on any JRE >= 11.
APPLET_RELEASE="${APPLET_RELEASE:-11}"
appletOut="$(mktemp -d)"; trap 'rm -rf "$appletOut"' EXIT
echo "Compiling applet (--release $APPLET_RELEASE) ..."
javac --release "$APPLET_RELEASE" -cp "$jcardsim:$math" -d "$appletOut" \
    $(find "$appletSrc" -name '*.java')
jar cf "$VDIR/libs/keycard-applet.jar" -C "$appletOut" .

# Versions that gate APDUs on a factory Ident certificate (4.0) also need the host SDK + BouncyCastle
# (resolved into the Gradle cache by the status-keycard build) for personalization at newCard() time.
if [ "$needsPersonalization" = "true" ]; then
    sdk_coord="$(getprop statusKeycardJavaSdk)"        # group:module:sha
    module="$(printf '%s' "$sdk_coord" | cut -d: -f2)" # lib | desktop
    sha="$(printf '%s' "$sdk_coord" | cut -d: -f3)"
    GRADLE_CACHE="${GRADLE_USER_HOME:-$HOME/.gradle}/caches"
    sdk_lib="$(find "$GRADLE_CACHE" -path "*status-keycard-java/$module/$sha/*/$module-$sha.jar" 2>/dev/null | head -1)"
    bcprov="$(find "$GRADLE_CACHE" -name 'bcprov-jdk15on-1.65.jar' 2>/dev/null | head -1)"
    [ -n "$sdk_lib" ] || { echo "ERROR: SDK jar $module-$sha.jar not found in $GRADLE_CACHE (build status-keycard first)"; exit 1; }
    [ -n "$bcprov" ]  || { echo "ERROR: bcprov-jdk15on-1.65.jar not found in $GRADLE_CACHE"; exit 1; }
    cp "$sdk_lib" "$VDIR/libs/status-keycard-java-lib.jar"
    cp "$bcprov"  "$HERE/libs/common/bcprov-jdk15on-1.65.jar"   # version-independent (shared)
fi

echo "Refreshed version $VERSION:"
ls -la "$VDIR/libs" "$HERE/libs/common"
echo
echo "Provenance — verify these match $PROPS:"
echo "  statusKeycardSha = $(git -C "$SK" rev-parse --short HEAD 2>/dev/null || echo unknown)"
echo "  jcardsimSha      = $(git -C "$SK/jcardsim" rev-parse --short HEAD 2>/dev/null || echo unknown)"
