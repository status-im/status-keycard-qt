#!/usr/bin/env bash

# Outputs go to out/core and versions/<v>/out (both gitignored).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

JAVAC_RELEASE="${JAVAC_RELEASE:-11}"

CORE_OUT="$HERE/out/core"
mkdir -p "$CORE_OUT"
echo "Compiling core (--release $JAVAC_RELEASE) ..."
javac --release "$JAVAC_RELEASE" -cp "$HERE/libs/common/*" -d "$CORE_OUT" \
    "$HERE"/src/im/status/keycardqt/sim/*.java

for vdir in "$HERE"/versions/*/; do
    v="$(basename "$vdir")"
    [ -d "${vdir}src" ] || continue
    [ -d "${vdir}libs" ] || { echo "Skipping version $v (no libs/ — run ./refresh-artifacts.sh $v)"; continue; }
    out="${vdir}out"
    mkdir -p "$out"
    echo "Compiling version $v (--release $JAVAC_RELEASE) ..."
    javac --release "$JAVAC_RELEASE" -cp "$CORE_OUT:$HERE/libs/common/*:${vdir}libs/*" -d "$out" \
        $(find "${vdir}src" -name '*.java')
done

echo "Built -> $HERE/out (core) + versions/*/out"
