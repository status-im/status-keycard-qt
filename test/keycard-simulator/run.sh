#!/usr/bin/env bash

# Runs the simulator server for a given applet version.
# Usage: ./run.sh [port] [version]      (version defaults to 3.2 — introduced in the keycard-qt commit #df00b931)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="${1:-9025}"
VERSION="${2:-3.2}"

VDIR="$HERE/versions/$VERSION"
PROPS="$VDIR/version.properties"

[ -d "$VDIR" ]  || { echo "ERROR: unknown applet version '$VERSION' (no $VDIR)"; exit 1; }
[ -f "$PROPS" ] || { echo "ERROR: missing $PROPS"; exit 1; }
mainClass="$(sed -n 's/^mainClass=//p' "$PROPS")"
[ -n "$mainClass" ] || { echo "ERROR: mainClass not set in $PROPS"; exit 1; }

# Free the port if a previous simulator instance is still bound to it (a leftover from an earlier
# session won't be tracked by the app, so it would otherwise fail with "Address already in use").
# Only kill our OWN leftover simulator; refuse to touch an unrelated process holding the port.
if command -v lsof >/dev/null 2>&1; then
    for pid in $(lsof -ti "tcp:$PORT" 2>/dev/null || true); do
        if ps -p "$pid" -o command= 2>/dev/null | grep -q 'keycardqt'; then
            echo "Port $PORT held by a previous simulator (pid $pid) — stopping it."
            kill "$pid" 2>/dev/null || true
        else
            echo "ERROR: port $PORT is in use by a non-simulator process (pid $pid); refusing to kill it:"
            ps -p "$pid" -o pid=,command= 2>/dev/null || true
            exit 1
        fi
    done
    # wait briefly for the OS to release the socket
    tries=0
    while lsof -ti "tcp:$PORT" >/dev/null 2>&1 && [ "$tries" -lt 20 ]; do
        sleep 0.2; tries=$((tries + 1))
    done
fi

CP="$HERE/out/core:$VDIR/out:$HERE/libs/common/*:$VDIR/libs/*"
echo "Starting keycard simulator: applet $VERSION, port $PORT, main $mainClass"

java_bin() {
    local c out
    for c in \
        ${JAVA_HOME:+"$JAVA_HOME/bin/java"} \
        /opt/homebrew/opt/openjdk*/libexec/openjdk.jdk/Contents/Home/bin/java \
        /usr/local/opt/openjdk*/libexec/openjdk.jdk/Contents/Home/bin/java \
        "$(command -v java 2>/dev/null || true)"
    do
        [ -x "$c" ] || continue
        out="$("$c" -version 2>&1 || true)"
        case "$out" in *"Unable to locate a Java Runtime"*) continue ;; esac
        echo "$c"
        return 0
    done
    return 1
}

JAVA_BIN="$(java_bin)" || { echo "ERROR: java not found; install a JRE >= 11 or set JAVA_HOME." >&2; exit 1; }
echo "Using java: $JAVA_BIN"
exec "$JAVA_BIN" -noverify -cp "$CP" "$mainClass" "$PORT"
