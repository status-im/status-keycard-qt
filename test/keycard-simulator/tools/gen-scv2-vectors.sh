#!/usr/bin/env bash

# Regenerates tools/scv2-vectors.json: SecureChannelV2 known-answer vectors from the real 4.0 applet
# (jcardsim) driven by the real host SDK, with randomness pinned (see GenScv2Vectors.java).
# Usage: ./tools/gen-scv2-vectors.sh [output.json]     (default: tools/scv2-vectors.json)
set -euo pipefail
TOOLS="$(cd "$(dirname "$0")" && pwd)"
HERE="$(dirname "$TOOLS")"
OUT_JSON="${1:-$TOOLS/scv2-vectors.json}"

"$HERE/build.sh" >/dev/null

V40="$HERE/versions/4.0"
CP="$HERE/out/core:$V40/out:$HERE/libs/common/*:$V40/libs/*"
TOOLS_OUT="$TOOLS/out"
mkdir -p "$TOOLS_OUT"
javac --release "${JAVAC_RELEASE:-11}" -cp "$CP" -d "$TOOLS_OUT" $(find "$TOOLS/src" -name '*.java')

tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT
java -noverify -cp "$TOOLS_OUT:$CP" im.status.keycardqt.sim.tools.GenScv2Vectors > "$tmp"
mv "$tmp" "$OUT_JSON"
trap - EXIT
echo "Wrote $OUT_JSON"
