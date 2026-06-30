# keycard-simulator

An **APDU-over-TCP server** that runs the **real Status Keycard applet** inside
[jcardsim](https://github.com/status-im/jcardsim), so `status-keycard-qt` (built with
`USE_SIMULATED_KEYCARD`) can drive a real card in tests without hardware. The C++
`SimulatedChannelBackend` is the socket client; this server runs the applet, so behaviour is
state-dependent like a physical card (real secp256k1 secure channel, PIN/PUK counters, pairing).

Running it needs **only a JVM** — the `status-keycard` checkout / JavaCard SDK / Gradle are needed
only to *regenerate* the vendored `libs/`.

## Versions

| version | secure channel | matches |
|---------|----------------|---------|
| **3.2** (default) | `SecureChannel` v1, password `PAIR` (`INS 0x12`) | keycard-qt `df00b931` (what the lib pins) |
| 4.0 | `SecureChannelV2` (cert-based, no `PAIR`) | a future keycard-qt with SCv2 support |

keycard-qt `df00b931` sends `INS_PAIR 0x12`, which 4.0 removed — so **3.2 is the default and the only
one wired to the app**. 4.0 is a ready scaffold (runs standalone, not driveable by the app yet).

## Layout

```
src/im/status/keycardqt/sim/        # version-NEUTRAL core (no im.status.keycard.* imports)
  SimProtocolServer.java            #   TCP protocol + per-id card map; delegates to a CardFactory
  CardFactory.java                  #   interface: CardSimulator newCard()
  CardInstall.java                  #   shared AIDs + install + assignUniqueInstanceUid()
  ExposedRuntime.java               #   exposes jcardsim's installed applet (for the UID patch)
libs/common/                        # version-independent: jcardsim, bcprov (bcprov only used by 4.0)
versions/<v>/
  libs/                             # keycard-applet, keycard-math (+ status-keycard-java for 4.0)
  src/.../v<v>/{Main,Card<v>Factory}.java   # entry point + that version's card recipe
  version.properties                # appletVersion, mainClass, needsPersonalization, provenance SHAs
build.sh  run.sh  refresh-artifacts.sh
```

3.2 and 4.0 applet jars share the same class names with different bytecode, so they **cannot share a
classpath**: the core is version-neutral, and each version's recipe is compiled/run against only its
own `libs/` (`run.sh` puts one version on the classpath).

## Card recipe (`Card<v>Factory.newCard()`)

- **3.2** — install KeycardApplet + NDEF + Cash + Ident, then `assignUniqueInstanceUid()`. That's a
  blank / post-`FactoryReset` card; the app drives INIT/pair/load-key over real APDUs.
- **4.0** — same, plus store a CA-signed Ident certificate (the 4.0 applet rejects every APDU until
  it has one). Still blank/no-key.

`assignUniqueInstanceUid()` overwrites the applet's instance UID with random bytes, because jcardsim's
RNG is deterministic and would otherwise give every card the same UID — colliding in the lib's
pairing storage (keyed by instance UID).

## Build & run

```bash
./build.sh
./run.sh 9025            # applet 3.2 (default) on TCP 9025
./run.sh 9025 4.0        # applet 4.0 (standalone only)
```
`run.sh` frees the port from a leftover simulator first, and passes `-noverify` (jcardsim's
`javacard.*` classes have no stackmap frames).

## Protocol (text, one request/response per line)

```
CREATE <id>            -> OK <atrHex>   create if absent (no-op if present)
RESET  <id>            -> OK            recreate fresh / blank
ATR    <id>            -> OK <atrHex>
APDU   <id> <apduHex>  -> OK <respHex>
PING                   -> OK
<other>                -> ERR <message>
```

Each `<id>` is an independent card (e.g. `A`, `B`) for multi-card flows; state persists until `RESET`.
To check a running server by hand (SELECT the keycard AID; a blank 3.2 card replies with its
secure-channel pubkey + `9000`):

```python
import socket
s = socket.create_connection(("127.0.0.1", 9025))
s.sendall(b"CREATE A\nAPDU A 00a4040009a00000080400010101\n")
print(s.recv(8192).decode())   # OK <ATR>  then  OK 8041<pubkey>9000
```

## Updating the vendored `libs/`

`libs/` is committed. Regenerate it only when bumping the applet/jcardsim, from a built
`status-keycard` checkout at the version's SHA (`version.properties`):

```bash
cd "$STATUS_KEYCARD_DIR" && git checkout <sha> && ./gradlew compileJava   # produces build/classes/java/main
cd - && STATUS_KEYCARD_DIR="$STATUS_KEYCARD_DIR" ./refresh-artifacts.sh <version>
./build.sh   # recompile, then commit the changed libs/
```
`STATUS_KEYCARD_DIR` is required (no default). If `./gradlew compileJava` rejects
`sourceCompatibility = 1.6`, compile the applet classes directly first:
`javac -cp "jcardsim/jcardsim-3.0.5-SNAPSHOT.jar:keycard-math/keycard-math.jar" -d build/classes/java/main src/main/java/im/status/keycard/*.java`.

## Provenance

| version | status-keycard | jcardsim | host SDK |
|---------|----------------|----------|----------|
| 3.2 | `72e9574` | `e1e351a` | `…:desktop:e898afd` (unused — install-only) |
| 4.0 | `9973c3d` | `e1e351a` | `…:lib:b4ed9ca` (+ bcprov 1.65 for personalization) |

SHAs are also recorded in each `versions/<v>/version.properties`.
